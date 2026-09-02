package keyfactor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ---------------------------------------------------------------------------
// Regression tests -- PR #210 full-review findings FIX-3 and FIX-4:
//
// FIX-3: Update() decoded `plan` from request.Plan, unlike the
// already-patched Create() (see resource_keyfactor_enrollment_pattern_
// create_unit_test.go's TestUnitEnrollmentPatternCreateResolvesUndeclared
// ComputedFieldsFromConfig). useStateOrNullModifier can leave a Computed
// attribute's PLANNED value genuinely Unknown -- e.g.
// policies.primary_key_algorithms, which is backed by a raw Go slice type
// ([]EnrollmentPatternResourceAlgorithm) that cannot represent an Unknown
// tftypes value at all. Decoding such a Plan crashes with "Value Conversion
// Error: unhandled unknown value" before Update()'s own logic ever runs.
// The fix makes Update() decode from request.Config instead, matching
// Create() -- Update() never reads request.Plan afterward, so a
// broken/still-resolving Plan can no longer crash it. This is proven below
// by handing Update() a Plan whose entire top-level raw value is Unknown:
// the old (request.Plan.Get) code would have crashed immediately decoding
// it; the fixed code never touches it at all.
//
// FIX-4: Update()'s fallback for the two write-only list attributes
// (associated_role_names, certificate_authority_ids -- see
// KeyfactorEnrollmentPatternState's doc comment) only checked
// config.X.Null, not config.X.Unknown. Unlike the raw-Go-slice fields FIX-3
// covers, types.List CAN represent Unknown without crashing decode -- e.g.
// `associated_role_names = [keyfactor_security_role.new_role.name]` where
// that role is created in the same apply leaves config.AssociatedRoleNames
// genuinely Unknown at Update() time. Without the Unknown check,
// plan.AssociatedRoleNames stayed Unknown all the way into the final state
// -- and a Terraform final state must never contain an Unknown value. The
// fix extends the fallback condition to also cover Unknown, falling back to
// this resource's own prior Terraform state (there is no other source of
// truth for these two write-only fields -- Command never echoes them back).
// ---------------------------------------------------------------------------

// newEnrollmentPatternUpdateTestServer answers the pre-update GET
// /EnrollmentPatterns/{id} with a minimal canned response and captures the
// body of the subsequent PUT /EnrollmentPatterns/{id} into *capturedPUTBody,
// echoing back a minimal, decodable response.
func newEnrollmentPatternUpdateTestServer(t *testing.T, capturedPUTBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id": 42, "Name": "Demo Pattern_TF"}`))
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			*capturedPUTBody = body
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id": 42, "Name": "Demo Pattern_TF"}`))
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitEnrollmentPatternUpdateDoesNotDependOnPlan is the direct
// regression test for FIX-3: Update() must succeed using only Config/State,
// even when handed a Plan whose entire top-level value is Unknown (standing
// in for "Plan still resolving" or any other corruption of that object).
// Before the fix, Update() called request.Plan.Get(ctx, &plan) -- decoding
// this Plan would have crashed immediately with "Value Conversion Error:
// unhandled unknown value", before any of Update()'s own logic ran.
func TestUnitEnrollmentPatternUpdateDoesNotDependOnPlan(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	server := newEnrollmentPatternUpdateTestServer(t, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	// Prior state: a fully-resolved, already-existing resource.
	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	state.AssociatedRoleNames = types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{types.String{Value: "InstanceAdmin"}},
	}
	state.Policies = &EnrollmentPatternResourcePolicy{}

	// Config: what the user actually declared -- fully valid/decodable, no
	// unknowns anywhere.
	config := state

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	configScratch := tfsdk.Plan{Schema: schema}
	if d := configScratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configScratch.Raw}

	// Plan: deliberately broken -- the entire top-level object is Unknown.
	// If Update() still decoded from request.Plan (the pre-fix behavior),
	// this crashes immediately.
	unknownPlanRaw := tftypes.NewValue(configScratch.Raw.Type(), tftypes.UnknownValue)
	planObj := tfsdk.Plan{Schema: schema, Raw: unknownPlanRaw}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf(
			"Update returned diagnostics (this is the live repro: decoding an Unknown Plan crashes with "+
				"\"Value Conversion Error ... unhandled unknown value\" -- Update() must not depend on "+
				"request.Plan at all): %+v",
			resp.Diagnostics,
		)
	}

	if len(putBody) == 0 {
		t.Fatal("no PUT /EnrollmentPatterns request was captured -- Update() did not complete")
	}
}

// TestUnitEnrollmentPatternUpdateResolvesUnknownAssociatedRoleNamesFromState
// is the direct regression test for FIX-4: when config.AssociatedRoleNames
// is genuinely Unknown (e.g. chained from a security role resource created
// in the same apply), Update() must fall back to this resource's own prior
// Terraform state -- there is no other source of truth for this write-only
// field -- rather than leaving the final state's associated_role_names
// Unknown.
func TestUnitEnrollmentPatternUpdateResolvesUnknownAssociatedRoleNamesFromState(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	server := newEnrollmentPatternUpdateTestServer(t, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	state.AssociatedRoleNames = types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{types.String{Value: "InstanceAdmin"}},
	}
	state.Policies = &EnrollmentPatternResourcePolicy{}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	// Config: associated_role_names is genuinely Unknown -- e.g. chained
	// from `keyfactor_security_role.new_role.name`, a resource created in
	// the same apply. types.List CAN represent Unknown (unlike the raw Go
	// slice fields FIX-3 covers), so this decodes without crashing -- the
	// bug is purely in what Update() does with it afterward.
	config := state
	config.AssociatedRoleNames = types.List{Unknown: true, ElemType: types.StringType}

	configScratch := tfsdk.Plan{Schema: schema}
	if d := configScratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configScratch.Raw}
	// Plan mirrors Config here -- FIX-3's test covers the "Plan disagrees
	// with / crashes independent of Config" case separately.
	planObj := tfsdk.Plan{Schema: schema, Raw: configScratch.Raw}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	var finalState KeyfactorEnrollmentPatternState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}

	if finalState.AssociatedRoleNames.Unknown {
		t.Fatal(
			"final state associated_role_names is Unknown -- a final Terraform state must never contain " +
				"an Unknown value; the config.Unknown fallback must resolve this from prior state",
		)
	}
	if finalState.AssociatedRoleNames.Null {
		t.Fatal("final state associated_role_names is Null, want the prior state's value (InstanceAdmin) preserved")
	}
	var got []string
	finalState.AssociatedRoleNames.ElementsAs(ctx, &got, false)
	if len(got) != 1 || got[0] != "InstanceAdmin" {
		t.Errorf("final state associated_role_names = %v, want [InstanceAdmin] (fallback to prior state)", got)
	}
}
