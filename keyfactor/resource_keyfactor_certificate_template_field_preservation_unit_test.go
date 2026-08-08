package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Unit tests — keyfactor_certificate_template Update() resetting fields
// besides allowed_requesters (dev-harness certificate_template_demo finding,
// completes #195).
//
// Live repro (provider fix/harness-bugs @ 51f4dc1 -> kfclab, Command 25.5):
// updating ONLY friendly_name on template 7 (AnyCA_lab-root-role) silently
// reset TWO unrelated fields to their zero values server-side:
// key_retention "FromIssuance" -> "None" and allow_one_click_renewals
// true -> false. Root cause: PUT /Templates is a full-replace endpoint, and
// buildTemplateUpdateRequest skips any plan field left Null/Unknown; the
// #195 fix (preserveAllowedRequesters) only fetched-and-preserved
// AllowedRequesters/UseAllowedRequesters before that PUT, leaving every
// other Optional field exposed to the same bug class.
//
// The fix (preserveUndeclaredTemplateFields, called unconditionally from
// Update() alongside preserveAllowedRequesters whenever any writable field
// is left undeclared -- see templateUpdateNeedsPreservationFetch) does a
// read-modify-write against a fresh GET /Templates/{id}, carrying forward
// every writable field the plan doesn't declare.
// ---------------------------------------------------------------------------

// newFieldPreservationTestServer returns an httptest server that answers
// GET /Templates/{id} with a canned template holding real, non-default
// values for every writable field (simulating "FromIssuance" key retention,
// one-click renewals enabled, etc.), and captures the body of any
// PUT /Templates request into *capturedPUTBody.
func newFieldPreservationTestServer(t *testing.T, capturedPUTBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(7)
			resp.SetCommonName("AnyCA_lab-root-role")
			resp.SetTemplateName("AnyCA Lab Root Role")
			resp.SetFriendlyName("OldFriendlyName")
			kr := v1.CSSCMSCoreEnumsKeyRetentionPolicy(1) // non-default retention policy ("FromIssuance"-equivalent)
			resp.KeyRetention = &kr
			resp.SetKeyRetentionDays(45)
			resp.SetAllowedEnrollmentTypes(2)
			resp.SetRequiresApproval(true)
			resp.SetAllowOneClickRenewals(true)
			resp.SetKeyUsage(160)
			resp.SetCertificateCleanupEnabled(true)
			resp.SetTimeAfterExpiration(30)
			units := v1.CSSCMSDataModelEnumsCertificateCleanupTimeUnits(1)
			resp.TimeAfterExpirationUnits = &units
			resp.SetDeleteWithArchivedKey(true)
			resp.SetUseAllowedRequesters(true)
			resp.AllowedRequesters = []string{"ExistingRole"}
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
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(7)
			resp.SetCommonName("AnyCA_lab-root-role")
			resp.SetTemplateName("AnyCA Lab Root Role")
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode PUT response: %v", err)
			}
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitCertificateTemplateUpdatePreservesUndeclaredFields is the direct
// regression test for the certificate_template_demo dev-harness finding: an
// Update() whose plan declares ONLY friendly_name (the exact live repro
// shape) must not clear every other undeclared writable field on the PUT
// /Templates payload. It must instead carry forward each field's CURRENT
// server-side value, fetched fresh via GET.
func TestUnitCertificateTemplateUpdatePreservesUndeclaredFields(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	server := newFieldPreservationTestServer(t, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	// Prior local state: matches the server's current (pre-update) values.
	state := blankTemplateState()
	state.ID = types.Int64{Value: 7}
	state.FriendlyName = types.String{Value: "OldFriendlyName"}
	state.KeyRetention = types.Int64{Value: 1}
	state.KeyRetentionDays = types.Int64{Value: 45}
	state.AllowedEnrollmentTypes = types.Int64{Value: 2}
	state.RequiresApproval = types.Bool{Value: true}
	state.AllowOneClickRenewals = types.Bool{Value: true}
	state.KeyUsage = types.Int64{Value: 160}
	state.CertificateCleanupEnabled = types.Bool{Value: true}
	state.TimeAfterExpiration = types.Int64{Value: 30}
	state.TimeAfterExpirationUnits = types.Int64{Value: 1}
	state.DeleteWithArchivedKey = types.Bool{Value: true}
	state.UseAllowedRequesters = types.Bool{Value: true}
	state.AllowedRequesters = stringSliceToTfList([]string{"ExistingRole"})

	// Plan: config declares ONLY friendly_name (a new value) -- every other
	// writable field is Null, exactly the live repro shape ("friendly_name
	// update silently reset KeyRetention/AllowOneClickRenewals").
	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 7}
	plan.FriendlyName = types.String{Value: "NewFriendlyName"}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
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

	// friendly_name: the newly-declared value must go through unchanged.
	if got, ok := onWire["FriendlyName"]; !ok || got != "NewFriendlyName" {
		t.Errorf("FriendlyName on the wire = %v, want \"NewFriendlyName\"", got)
	}

	// key_retention: undeclared, must be preserved as the server's current
	// non-default value (1), not omitted/reset to "None" (0).
	if got, ok := onWire["KeyRetention"]; !ok || got == nil {
		t.Errorf(
			"PUT /Templates payload has no KeyRetention -- this reproduces the certificate_template_demo "+
				"finding: an update that only declares friendly_name clears key_retention server-side. "+
				"Full payload: %s", putBody,
		)
	} else if gotF, ok := got.(float64); !ok || gotF != 1 {
		t.Errorf("KeyRetention on the wire = %v, want 1 (preserved from server)", got)
	}

	// key_retention_days: undeclared, must be preserved as 45 -- Command
	// rejects a retention-policy update with days omitted/zero (this is also
	// the exact field combination behind the template_role_binding defect).
	if got, ok := onWire["KeyRetentionDays"]; !ok || got == nil {
		t.Errorf("PUT /Templates payload has no KeyRetentionDays, want 45 preserved. Full payload: %s", putBody)
	} else if gotF, ok := got.(float64); !ok || gotF != 45 {
		t.Errorf("KeyRetentionDays on the wire = %v, want 45 (preserved from server)", got)
	}

	// allow_one_click_renewals: undeclared, must be preserved as true, not
	// reset to false -- the other field the harness observed resetting.
	if got, ok := onWire["AllowOneClickRenewals"]; !ok || got == nil {
		t.Errorf(
			"PUT /Templates payload has no AllowOneClickRenewals -- this reproduces the certificate_template_demo "+
				"finding: an update that only declares friendly_name clears allow_one_click_renewals server-side "+
				"(observed live: true -> false). Full payload: %s", putBody,
		)
	} else if gotB, ok := got.(bool); !ok || !gotB {
		t.Errorf("AllowOneClickRenewals on the wire = %v, want true (preserved from server)", got)
	}

	// requires_approval / key_usage / allowed_enrollment_types: undeclared,
	// must also be preserved (same bug class, same fix).
	if got, ok := onWire["RequiresApproval"]; !ok || got != true {
		t.Errorf("RequiresApproval on the wire = %v, want true (preserved from server)", got)
	}
	if got, ok := onWire["KeyUsage"]; !ok || got == nil {
		t.Errorf("KeyUsage on the wire = %v, want 160 (preserved from server)", got)
	} else if gotF, ok := got.(float64); !ok || gotF != 160 {
		t.Errorf("KeyUsage on the wire = %v, want 160 (preserved from server)", got)
	}
	if got, ok := onWire["AllowedEnrollmentTypes"]; !ok || got == nil {
		t.Errorf("AllowedEnrollmentTypes on the wire = %v, want 2 (preserved from server)", got)
	} else if gotF, ok := got.(float64); !ok || gotF != 2 {
		t.Errorf("AllowedEnrollmentTypes on the wire = %v, want 2 (preserved from server)", got)
	}

	// allowed_requesters: undeclared, must also still be preserved (the
	// original #195 field), proving the two preservation paths coexist.
	requesters, ok := onWire["AllowedRequesters"].([]interface{})
	if !ok || len(requesters) != 1 || requesters[0] != "ExistingRole" {
		t.Errorf("AllowedRequesters on the wire = %v, want exactly [\"ExistingRole\"]", onWire["AllowedRequesters"])
	}

	// v25+ cleanup fields: undeclared, must also be preserved.
	if got, ok := onWire["CertificateCleanupEnabled"]; !ok || got != true {
		t.Errorf("CertificateCleanupEnabled on the wire = %v, want true (preserved from server)", got)
	}
	if got, ok := onWire["TimeAfterExpiration"]; !ok || got == nil {
		t.Errorf("TimeAfterExpiration on the wire = %v, want 30 (preserved from server)", got)
	} else if gotF, ok := got.(float64); !ok || gotF != 30 {
		t.Errorf("TimeAfterExpiration on the wire = %v, want 30 (preserved from server)", got)
	}
	if got, ok := onWire["DeleteWithArchivedKey"]; !ok || got != true {
		t.Errorf("DeleteWithArchivedKey on the wire = %v, want true (preserved from server)", got)
	}
}
