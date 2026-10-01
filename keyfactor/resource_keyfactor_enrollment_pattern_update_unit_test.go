package keyfactor

import (
	"context"
	"encoding/json"
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
// Regression tests: two Update() bugs.
//
// Config-decode bug: Update() decoded `plan` from request.Plan, unlike the
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
// Unknown-fallback bug: Update()'s fallback for certificate_authority_ids
// (see KeyfactorEnrollmentPatternState's doc comment) only checked
// config.CertificateAuthorityIds.Null, not .Unknown. types.Set CAN
// represent Unknown without crashing decode (unlike the raw-Go-slice
// fields the config-decode fix covers) -- e.g.
// `certificate_authority_ids = [keyfactor_certificate_authority.new_ca.id]`
// where that CA is created in the same apply leaves
// config.CertificateAuthorityIds genuinely Unknown at Update() time.
// Without the Unknown check, it stayed Unknown in the final state -- and
// a Terraform final state must never contain an Unknown value. The fix
// extends the fallback condition to also cover Unknown, falling back (via
// preserveUndeclaredEnrollmentPatternFields) to the fresh pre-update GET's
// own CertificateAuthorities expansion.
// ---------------------------------------------------------------------------

// newEnrollmentPatternUpdateTestServer answers the pre-update GET
// /EnrollmentPatterns/{id} with a minimal canned response and captures the
// body of the subsequent PUT /EnrollmentPatterns/{id} into
// *capturedPUTBody, echoing back the same minimal response.
func newEnrollmentPatternUpdateTestServer(t *testing.T, capturedPUTBody *[]byte) *httptest.Server {
	t.Helper()
	const cannedResponse = `{"Id": 42, "Name": "Demo Pattern_TF"}`
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cannedResponse))
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			*capturedPUTBody = body
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cannedResponse))
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitEnrollmentPatternUpdateDoesNotDependOnPlan is the direct
// regression test: Update() must succeed using only Config/State,
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

// ---------------------------------------------------------------------------
// Regression test: lifecycle.ignore_changes = [associated_role_names] must
// preserve roles added by role_binding resources through an Update().
//
// Root cause: Update() decoded all fields from request.Config. Terraform Core
// injects the prior-state value of an ignored attribute into request.Plan, but
// Config always holds the literal config expression. When Config declares
// `associated_role_names = ["InstanceAdmin"]` and a role_binding previously
// added "Administrator" (making the prior state = {"InstanceAdmin","Administrator"}),
// lifecycle.ignore_changes injects {"InstanceAdmin","Administrator"} into Plan
// but Config still has only ["InstanceAdmin"]. Reading Config caused Update()
// to send only ["InstanceAdmin"], producing "Provider produced inconsistent
// result after apply" because the plan promised both roles.
//
// The fix: after decoding Config, overwrite associated_role_names with the
// Plan value (types.Set can safely represent Unknown unlike raw Go slices).
// ---------------------------------------------------------------------------

// TestUnitEnrollmentPatternUpdateUsesPlanAssociatedRoleNamesNotConfig verifies
// that when request.Plan carries extra roles (injected by Terraform Core's
// lifecycle.ignore_changes from the prior state), Update() sends ALL of them
// in the PUT body rather than only the roles the Config declares.
func TestUnitEnrollmentPatternUpdateUsesPlanAssociatedRoleNamesNotConfig(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	server := newEnrollmentPatternUpdateTestServer(t, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	// Config: what the user declared in HCL -- only InstanceAdmin.
	configState := blankEnrollmentPatternState()
	configState.Name = types.String{Value: "Demo Pattern_TF"}
	configState.TemplateId = types.Int64{Value: 6}
	configState.UseADPermissions = types.Bool{Value: false}
	configState.AssociatedRoleNames = types.Set{
		ElemType: types.StringType,
		Elems:    []attr.Value{types.String{Value: "InstanceAdmin"}},
	}

	configScratch := tfsdk.Plan{Schema: schema}
	if d := configScratch.Set(ctx, &configState); d.HasError() {
		t.Fatalf("test setup: configScratch.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configScratch.Raw}

	// Plan: lifecycle.ignore_changes = [associated_role_names] causes Terraform
	// Core to inject the prior state value {"InstanceAdmin","Administrator"} into
	// request.Plan. Config still holds only ["InstanceAdmin"], but the Plan
	// carries both because "Administrator" was added by a role_binding resource
	// on a previous apply.
	planState := configState
	planState.AssociatedRoleNames = types.Set{
		ElemType: types.StringType,
		Elems: []attr.Value{
			types.String{Value: "InstanceAdmin"},
			types.String{Value: "Administrator"},
		},
	}
	planScratch := tfsdk.Plan{Schema: schema}
	if d := planScratch.Set(ctx, &planState); d.HasError() {
		t.Fatalf("test setup: planScratch.Set returned diagnostics: %+v", d)
	}

	// Prior state: needs the resource ID so Update() can call GetById + PutById.
	stateState := blankEnrollmentPatternState()
	stateState.ID = types.Int64{Value: 42}
	stateState.Name = types.String{Value: "Demo Pattern_TF"}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &stateState); d.HasError() {
		t.Fatalf("test setup: stateObj.Set returned diagnostics: %+v", d)
	}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planScratch, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}
	if len(putBody) == 0 {
		t.Fatal("Update() made no PUT request")
	}

	// Verify the PUT body's AssociatedRoles contains BOTH roles. Before the
	// fix, Update decoded associated_role_names from Config (= ["InstanceAdmin"])
	// and omitted "Administrator" from the PUT -- contradicting the Plan's
	// {"InstanceAdmin","Administrator"} and triggering "Provider produced
	// inconsistent result after apply".
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(putBody, &bodyMap); err != nil {
		t.Fatalf("failed to parse PUT body as JSON: %v\nBody: %s", err, putBody)
	}
	rolesRaw, ok := bodyMap["AssociatedRoles"]
	if !ok {
		t.Fatalf("PUT body missing AssociatedRoles field; body: %s", putBody)
	}
	rolesSlice, _ := rolesRaw.([]interface{})
	sentRoles := make(map[string]bool, len(rolesSlice))
	for _, v := range rolesSlice {
		if s, ok := v.(string); ok {
			sentRoles[s] = true
		}
	}
	for _, want := range []string{"InstanceAdmin", "Administrator"} {
		if !sentRoles[want] {
			t.Errorf(
				"PUT body AssociatedRoles missing %q; got %v\n"+
					"(Before fix: Update read associated_role_names from Config=[\"InstanceAdmin\"] "+
					"instead of Plan=[\"InstanceAdmin\",\"Administrator\"], dropping the role preserved "+
					"by lifecycle.ignore_changes and causing \"Provider produced inconsistent result after apply\")",
				want, rolesSlice,
			)
		}
	}
}
