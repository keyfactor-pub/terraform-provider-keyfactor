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
)

// ---------------------------------------------------------------------------
// Regression test — full-review round 5 endorsed advisory: the
// templateUpdateNeedsPreservationFetch gate (removed by this change; see
// preserveUndeclaredTemplateFields and Update() in
// resource_keyfactor_certificate_template.go) only checked
// plan.TemplatePolicy == nil to decide whether a preservation GET was
// needed, but preserveUndeclaredTemplateFields does more than that once
// TemplatePolicy is non-nil: it ALSO fills any individual nested
// template_policy field (e.g. certificate_owner_role) left null/unknown
// WITHIN an otherwise-declared template_policy block. A plan with every
// top-level writable field declared, and a template_policy block that
// declares every nested field EXCEPT ONE, satisfied the old gate's "fully
// declared, skip the fetch" condition -- so the fetch never ran, `current`
// stayed nil, preserveUndeclaredTemplateFields no-op'd (current == nil),
// and the one undeclared nested field was silently omitted from the PUT and
// cleared server-side. Exactly the #195 bug class, reintroduced by the
// gate's own "no extra GET when everything's declared" optimization.
//
// The fix makes the preservation GET unconditional, so this corner case is
// preserved along with every other one preserveUndeclaredTemplateFields
// already handles.
// ---------------------------------------------------------------------------

// TestUnitCertificateTemplateUpdatePreservesNestedPolicyFieldWhenTopLevelFullyDeclared
// is the direct regression test: plan declares every top-level writable
// field (satisfying the old gate's skip condition) AND declares
// template_policy, but leaves ONE nested field
// (template_policy.certificate_owner_role) undeclared. The PUT payload must
// still carry that field's current server-side value, not omit/clear it.
func TestUnitCertificateTemplateUpdatePreservesNestedPolicyFieldWhenTopLevelFullyDeclared(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	var getHits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			getHits++
			w.Header().Set("Content-Type", "application/json")
			// CertificateOwnerRole is 2 (a real, non-default server-side
			// value) -- this is what must survive into the PUT payload even
			// though plan doesn't declare it.
			_, _ = w.Write([]byte(`{
				"Id": 21,
				"CommonName": "PolicyTemplate",
				"TemplateName": "Policy Template",
				"FriendlyName": "DeclaredFriendlyName",
				"TemplatePolicy": {
					"AllowKeyReuse": false,
					"AllowWildcards": false,
					"RFCEnforcement": true,
					"CertificateOwnerRole": 2,
					"DefaultCertificateOwnerRoleId": null,
					"DefaultCertificateOwnerRoleName": null
				}
			}`))
		case r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			putBody = body
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"Id": 21,
				"CommonName": "PolicyTemplate",
				"TemplateName": "Policy Template",
				"FriendlyName": "DeclaredFriendlyName"
			}`))
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	state := blankTemplateState()
	state.ID = types.Int64{Value: 21}
	state.FriendlyName = types.String{Value: "OldFriendlyName"}

	// Plan: every top-level writable field is declared (the old gate's
	// "skip the fetch" condition), template_policy itself is declared
	// (non-nil), but CertificateOwnerRole within it is left undeclared
	// (Null) -- a partially-declared nested block.
	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 21}
	plan.FriendlyName = types.String{Value: "DeclaredFriendlyName"}
	plan.UseAllowedRequesters = types.Bool{Value: false}
	plan.AllowedRequesters = types.List{Elems: []attr.Value{}, ElemType: types.StringType}
	plan.KeyRetention = types.Int64{Value: 1}
	plan.KeyRetentionDays = types.Int64{Value: 30}
	plan.AllowedEnrollmentTypes = types.Int64{Value: 2}
	plan.RequiresApproval = types.Bool{Value: false}
	plan.AllowOneClickRenewals = types.Bool{Value: true}
	plan.KeyUsage = types.Int64{Value: 5}
	plan.CertificateCleanupEnabled = types.Bool{Value: true}
	plan.TimeAfterExpiration = types.Int64{Value: 7}
	plan.TimeAfterExpirationUnits = types.Int64{Value: 0}
	plan.DeleteWithArchivedKey = types.Bool{Value: false}
	plan.TemplateRegexes = []TemplateRegexEntry{}
	plan.TemplateDefaults = []TemplateDefaultEntry{}
	plan.EnrollmentFields = []TemplateEnrollmentFieldEntry{}
	plan.MetadataFields = []TemplateMetadataFieldEntry{}
	plan.TemplatePolicy = &TemplatePolicyState{
		AllowKeyReuse:                   types.Bool{Value: false},
		AllowWildcards:                  types.Bool{Value: false},
		RFCEnforcement:                  types.Bool{Value: true},
		CertificateOwnerRole:            types.Int64{Null: true}, // the one undeclared nested field
		DefaultCertificateOwnerRoleID:   types.Int64{Null: true},
		DefaultCertificateOwnerRoleName: types.String{Null: true},
	}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	// Config mirrors plan's Raw verbatim (this test builds plan directly
	// rather than via PlanResourceChange, so plan's declared/undeclared
	// shape already IS config's).
	configObj := tfsdk.Config{Schema: schema, Raw: planObj.Raw}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	if getHits != 1 {
		t.Fatalf("expected exactly 1 preservation GET (now unconditional), got %d", getHits)
	}
	if len(putBody) == 0 {
		t.Fatal("no PUT /Templates request was captured")
	}

	var onWire map[string]interface{}
	if err := json.Unmarshal(putBody, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}

	pol, ok := onWire["TemplatePolicy"].(map[string]interface{})
	if !ok {
		t.Fatalf("PUT /Templates payload has no TemplatePolicy object. Full payload: %s", putBody)
	}
	got, ok := pol["CertificateOwnerRole"]
	if !ok || got == nil {
		t.Fatalf(
			"TemplatePolicy.CertificateOwnerRole on the wire = %v, want 2 preserved from the server -- this "+
				"reproduces the endorsed advisory's finding: a plan fully declared at the top level except one "+
				"nested template_policy field skipped the (gated) preservation fetch entirely and silently "+
				"cleared that field. Full payload: %s", got, putBody,
		)
	}
	if gotF, ok := got.(float64); !ok || gotF != 2 {
		t.Errorf("TemplatePolicy.CertificateOwnerRole on the wire = %v, want 2 (preserved from server)", got)
	}
}
