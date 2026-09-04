package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests — full-review round 2 finding #1 (correctness, medium):
//
// A config that declares one of the writable collection attributes as an
// explicit empty list (e.g. `template_regexes = []` or
// `allowed_requesters = []`) is a real "clear this" declaration, distinct
// from leaving the attribute out of config entirely ("undeclared" -- see
// preserveUndeclaredTemplateFields/TestUnitCertificateTemplateUpdatePreservesNonEmptyCollections
// for that path). Before this fix:
//
//  1. preserveUndeclaredTemplateFields keyed off len(plan.X) == 0, which
//     can't tell "declared []" apart from "undeclared" (both are
//     zero-length) -- so a declared-empty nested collection was silently
//     refilled from a fresh GET and the clear never reached the wire.
//  2. templateResponseToState always maps a zero-length AllowedRequesters
//     response to types.List{Null: true}, regardless of why it's empty --
//     so even though the AllowedRequesters clear DID reach the wire, the
//     applied final state came back null while the plan was a known empty
//     list, and Terraform core rejected the apply with "Provider produced
//     inconsistent result after apply" on every single application (a
//     permanent, non-convergent failure since the next Read reproduces the
//     same null vs. the user's still-declared []).
//
// The fix: preserveUndeclaredTemplateFields/templateUpdateNeedsPreservationFetch
// now key off nil-ness (which the reflection layer preserves faithfully --
// see their doc comments) instead of len(), and Read/Update reconcile the
// final applied state's null-vs-empty shape against prior state/plan via
// preserveListEmptyVsNull (native slices) and preserveTfListEmptyVsNull
// (types.List), mirroring the certificate_store_type resource's issue #192
// fix.
// ---------------------------------------------------------------------------

// newDeclaredEmptyTestServer returns an httptest server whose GET
// /Templates/{id} response carries a non-empty TemplateRegexes and
// AllowedRequesters (standing in for "the server currently has stuff to
// clear"), and whose PUT /Templates response echoes back an EMPTY
// TemplateRegexes/AllowedRequesters (simulating Command actually carrying out
// the clear this apply declared).
func newDeclaredEmptyTestServer(t *testing.T, capturedPUTBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(9)
			resp.SetCommonName("DeclaredEmptyTemplate")
			resp.SetTemplateName("Declared Empty Template")
			resp.SetFriendlyName("OldFriendlyName")
			resp.SetUseAllowedRequesters(true)
			resp.AllowedRequesters = []string{"ExistingRole"}

			rx := v1.TemplatesTemplateRegexRequestResponseModel{}
			rx.SetSubjectPart("CN")
			rx.SetRegex(".*")
			resp.TemplateRegexes = []v1.TemplatesTemplateRegexRequestResponseModel{rx}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode GET response: %v", err)
			}
		case r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			*capturedPUTBody = body
			// Command actually carried out the clear: echo back empty
			// collections, not the pre-update ones.
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(9)
			resp.SetCommonName("DeclaredEmptyTemplate")
			resp.SetTemplateName("Declared Empty Template")
			resp.SetFriendlyName("NewFriendlyName")
			resp.SetUseAllowedRequesters(false)
			resp.AllowedRequesters = nil
			resp.TemplateRegexes = nil
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode PUT response: %v", err)
			}
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitCertificateTemplateUpdateDeclaredEmptyCollectionClears is the direct
// regression test for finding #1a: a plan that declares `template_regexes =
// []` (a non-nil, zero-length Go slice -- exactly what the reflection layer
// produces for a config-declared empty list) must NOT be refilled from the
// server by preserveUndeclaredTemplateFields, must omit TemplateRegexes from
// the PUT /Templates payload (Command then clears it server-side, per the
// full-replace semantics documented on preserveUndeclaredTemplateFields), and
// the final applied state must read back as a known EMPTY list -- matching
// the plan -- not null and not the pre-update non-empty value.
func TestUnitCertificateTemplateUpdateDeclaredEmptyCollectionClears(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	server := newDeclaredEmptyTestServer(t, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	state := blankTemplateState()
	state.ID = types.Int64{Value: 9}
	state.FriendlyName = types.String{Value: "OldFriendlyName"}
	state.UseAllowedRequesters = types.Bool{Value: true}
	state.AllowedRequesters = stringSliceToTfList([]string{"ExistingRole"})
	state.TemplateRegexes = []TemplateRegexEntry{
		{SubjectPart: types.String{Value: "CN"}, Regex: types.String{Value: ".*"}, Error: types.String{Null: true}, CaseSensitive: types.Bool{Value: false}},
	}

	// Plan: template_regexes is explicitly declared as [] (a real Go
	// non-nil, zero-length slice -- what config `template_regexes = []`
	// actually produces via the reflection layer, as opposed to leaving the
	// field out of the struct entirely, which is nil). friendly_name also
	// changes so the update has something to do; every other field is left
	// undeclared (nil) so a preservation GET still happens, exercising the
	// "declared-empty must survive that GET pass" path directly.
	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 9}
	plan.FriendlyName = types.String{Value: "NewFriendlyName"}
	plan.TemplateRegexes = []TemplateRegexEntry{}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	// Confirm the test setup actually produces the shape this test claims:
	// a known, non-null, zero-element list on the plan (not null).
	var plannedRegexes attr.Value
	if d := planObj.GetAttribute(ctx, path.Root("template_regexes"), &plannedRegexes); d.HasError() {
		t.Fatalf("GetAttribute(template_regexes) on plan: %+v", d)
	}
	if plannedRegexes == nil || plannedRegexes.IsNull() {
		t.Fatalf("test setup: planned template_regexes is null, want a known empty list")
	}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	// Config: these tests build plan directly rather than by running
	// PlanResourceChange, so plan's declared/undeclared shape already IS the
	// config's declared/undeclared shape here -- reuse planObj's Raw value
	// verbatim so preserveUndeclaredTemplateFields's config-declaredness check
	// (full-review round 5 [HIGH]) sees the same thing this test's plan does.
	configObj := tfsdk.Config{Schema: schema, Raw: planObj.Raw}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	if len(putBody) == 0 {
		t.Fatal("no PUT /Templates request was captured")
	}
	var onWire map[string]interface{}
	if err := json.Unmarshal(putBody, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}

	// The clear must actually reach the wire: TemplateRegexes must not carry
	// the pre-update, server-side entry through. Before the fix,
	// preserveUndeclaredTemplateFields refilled it from the GET response
	// (len(plan.TemplateRegexes) == 0 couldn't tell "declared []" from
	// "undeclared"), so the CN regex would silently survive the "clear".
	if regexes, ok := onWire["TemplateRegexes"].([]interface{}); ok && len(regexes) > 0 {
		t.Fatalf(
			"TemplateRegexes on the wire = %v, want empty/omitted -- this reproduces finding #1a: a declared "+
				"`template_regexes = []` was silently refilled from the server instead of clearing. Full payload: %s",
			onWire["TemplateRegexes"], putBody,
		)
	}

	// The final applied state must read back as a known EMPTY list (matching
	// the plan), not null. This is the actual Terraform-core consistency
	// check: a null final value here would still be "inconsistent" against
	// the plan's known empty list, exactly like finding #1b for
	// allowed_requesters below.
	var finalRegexes attr.Value
	if d := resp.State.GetAttribute(ctx, path.Root("template_regexes"), &finalRegexes); d.HasError() {
		t.Fatalf("GetAttribute(template_regexes) on final state: %+v", d)
	}
	if finalRegexes == nil || finalRegexes.IsNull() {
		t.Fatalf(
			"final state template_regexes is null, want a known empty list matching the plan -- a null final " +
				"value here is exactly what \"Provider produced inconsistent result after apply\" flags against " +
				"a planned known-empty list",
		)
	}
	list, ok := finalRegexes.(types.List)
	if !ok {
		t.Fatalf("final state template_regexes is not types.List: %T", finalRegexes)
	}
	if len(list.Elems) != 0 {
		t.Errorf("final state template_regexes has %d elements, want 0 (cleared)", len(list.Elems))
	}
}

// TestUnitCertificateTemplateUpdateDeclaredEmptyAllowedRequestersClears is the
// direct regression test for finding #1b: a plan that declares
// `allowed_requesters = []` must apply cleanly and read back as a known EMPTY
// list, not null, even though templateResponseToState always maps a
// zero-length server response to types.List{Null: true} regardless of why
// it's empty.
func TestUnitCertificateTemplateUpdateDeclaredEmptyAllowedRequestersClears(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	server := newDeclaredEmptyTestServer(t, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	state := blankTemplateState()
	state.ID = types.Int64{Value: 9}
	state.FriendlyName = types.String{Value: "OldFriendlyName"}
	state.UseAllowedRequesters = types.Bool{Value: true}
	state.AllowedRequesters = stringSliceToTfList([]string{"ExistingRole"})
	state.TemplateRegexes = []TemplateRegexEntry{
		{SubjectPart: types.String{Value: "CN"}, Regex: types.String{Value: ".*"}, Error: types.String{Null: true}, CaseSensitive: types.Bool{Value: false}},
	}

	// Plan: allowed_requesters is explicitly declared as a known, non-null,
	// zero-element list (`allowed_requesters = []` in HCL). use_allowed_requesters
	// is declared false to match. Every other field is left undeclared so a
	// preservation GET still happens.
	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 9}
	plan.FriendlyName = types.String{Value: "NewFriendlyName"}
	plan.UseAllowedRequesters = types.Bool{Value: false}
	plan.AllowedRequesters = types.List{Elems: []attr.Value{}, ElemType: types.StringType}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	// Confirm the test setup: a known, non-null, zero-element list on the
	// plan.
	var plannedRequesters attr.Value
	if d := planObj.GetAttribute(ctx, path.Root("allowed_requesters"), &plannedRequesters); d.HasError() {
		t.Fatalf("GetAttribute(allowed_requesters) on plan: %+v", d)
	}
	if plannedRequesters == nil || plannedRequesters.IsNull() {
		t.Fatalf("test setup: planned allowed_requesters is null, want a known empty list")
	}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	// Config: these tests build plan directly rather than by running
	// PlanResourceChange, so plan's declared/undeclared shape already IS the
	// config's declared/undeclared shape here -- reuse planObj's Raw value
	// verbatim so preserveUndeclaredTemplateFields's config-declaredness check
	// (full-review round 5 [HIGH]) sees the same thing this test's plan does.
	configObj := tfsdk.Config{Schema: schema, Raw: planObj.Raw}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	if len(putBody) == 0 {
		t.Fatal("no PUT /Templates request was captured")
	}
	var onWire map[string]interface{}
	if err := json.Unmarshal(putBody, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}
	if requesters, ok := onWire["AllowedRequesters"].([]interface{}); ok && len(requesters) > 0 {
		t.Fatalf("AllowedRequesters on the wire = %v, want empty/omitted (clear declared)", onWire["AllowedRequesters"])
	}

	// The final applied state must read back as a known EMPTY list, matching
	// the plan -- not null (finding #1b: templateResponseToState always maps
	// an empty server array to types.List{Null: true}).
	var finalRequesters attr.Value
	if d := resp.State.GetAttribute(ctx, path.Root("allowed_requesters"), &finalRequesters); d.HasError() {
		t.Fatalf("GetAttribute(allowed_requesters) on final state: %+v", d)
	}
	if finalRequesters == nil || finalRequesters.IsNull() {
		t.Fatalf(
			"final state allowed_requesters is null, want a known empty list matching the plan -- this " +
				"reproduces finding #1b: \"Provider produced inconsistent result after apply\" against a " +
				"planned known-empty list, and every subsequent plan re-diffs null vs [] forever",
		)
	}
	list, ok := finalRequesters.(types.List)
	if !ok {
		t.Fatalf("final state allowed_requesters is not types.List: %T", finalRequesters)
	}
	if len(list.Elems) != 0 {
		t.Errorf("final state allowed_requesters has %d elements, want 0 (cleared)", len(list.Elems))
	}
}

// TestUnitCertificateTemplateReadPreservesDeclaredEmptyShape is the Read()-side
// companion: once a declared-empty clear has been applied (prior state holds
// a known empty list for allowed_requesters/template_regexes, per the Update
// tests above), a subsequent Read() refresh must keep reading back a known
// empty list -- not flip to null -- or every future plan would show a
// spurious null-vs-[] diff forever (the "permanent re-diff" half of finding
// #1b).
func TestUnitCertificateTemplateReadPreservesDeclaredEmptyShape(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
		resp := v1.TemplatesTemplateRetrievalResponse{}
		resp.SetId(9)
		resp.SetCommonName("DeclaredEmptyTemplate")
		resp.SetTemplateName("Declared Empty Template")
		resp.SetFriendlyName("NewFriendlyName")
		resp.SetUseAllowedRequesters(false)
		resp.AllowedRequesters = nil
		resp.TemplateRegexes = nil
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("failed to encode GET response: %v", err)
		}
	}))
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	// Prior state: the clear already applied -- both collections are known
	// EMPTY lists (not null), exactly what the Update fix above produces.
	state := blankTemplateState()
	state.ID = types.Int64{Value: 9}
	state.FriendlyName = types.String{Value: "NewFriendlyName"}
	state.AllowedRequesters = types.List{Elems: []attr.Value{}, ElemType: types.StringType}
	state.TemplateRegexes = []TemplateRegexEntry{}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned diagnostics: %+v", resp.Diagnostics)
	}

	var finalRequesters attr.Value
	if d := resp.State.GetAttribute(ctx, path.Root("allowed_requesters"), &finalRequesters); d.HasError() {
		t.Fatalf("GetAttribute(allowed_requesters) on refreshed state: %+v", d)
	}
	if finalRequesters == nil || finalRequesters.IsNull() {
		t.Fatalf("refreshed allowed_requesters is null, want a known empty list preserved from prior state")
	}

	var finalRegexes attr.Value
	if d := resp.State.GetAttribute(ctx, path.Root("template_regexes"), &finalRegexes); d.HasError() {
		t.Fatalf("GetAttribute(template_regexes) on refreshed state: %+v", d)
	}
	if finalRegexes == nil || finalRegexes.IsNull() {
		t.Fatalf("refreshed template_regexes is null, want a known empty list preserved from prior state")
	}
}
