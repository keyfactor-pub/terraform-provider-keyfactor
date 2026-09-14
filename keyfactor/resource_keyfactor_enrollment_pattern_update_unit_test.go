package keyfactor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
