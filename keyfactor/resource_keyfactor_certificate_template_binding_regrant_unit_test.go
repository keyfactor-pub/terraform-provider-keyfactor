package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression test — full-review round 5 [HIGH]: Update() silently re-granting
// a role that keyfactor_template_role_binding's Delete already revoked
// earlier in the same apply.
//
// Setup, mirroring the exact interleaving the finding describes:
//
//  1. allowed_requesters is managed ONLY via keyfactor_template_role_binding
//     -- the template config never declares allowed_requesters or
//     use_allowed_requesters at all.
//  2. This resource's prior Terraform state still holds a role
//     ("RevokedRole") that a keyfactor_template_role_binding resource had
//     previously granted (absorbed into state by a prior Read -- see
//     templateResponseToState).
//  3. The apply also changes an unrelated attribute (friendly_name), which
//     is what makes the framework mark the Computed, config-null
//     allowed_requesters Unknown before useStateOrNullModifier resolves it
//     -- so the plan this test builds pins allowed_requesters/
//     use_allowed_requesters to that STALE state value, exactly like a real
//     plan would (this test constructs plan directly rather than running
//     PlanResourceChange, so it reproduces that pinned shape by hand).
//  4. In the same apply, Terraform destroys the keyfactor_template_role_binding
//     for RevokedRole BEFORE this template's Update runs -- removeRoleFromTemplate
//     PUTs the template with the role already removed server-side. This
//     test's fake GET /Templates/{id} handler stands in for that: it
//     returns an ALREADY-EMPTY AllowedRequesters, proving the role is gone
//     server-side by the time Update()'s preservation fetch runs.
//
// Before the fix, preserveUndeclaredTemplateFields keyed the "does the fresh
// GET win over plan" decision on plan null-ness. Here plan is NON-null (it
// was pinned to the stale state value by step 3), so the fresh GET was
// skipped and buildTemplateUpdateRequest re-PUT the stale ["RevokedRole"]
// list with UseAllowedRequesters=true -- silently re-granting the role the
// binding resource had just revoked, with no diff and no error.
//
// The fix keys that decision on CONFIG declaredness instead: config never
// declared allowed_requesters/use_allowed_requesters here, so the fresh GET
// (empty) must always win over the stale pinned plan value, regardless of
// plan's null-ness.
func TestUnitCertificateTemplateUpdateDoesNotResurrectBindingRevokedRole(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	var getHits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			getHits++
			// The binding resource's Delete already ran its removeRoleFromTemplate
			// PUT before this Update()'s own preservation GET -- the role is
			// already gone server-side.
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(11)
			resp.SetCommonName("BindingManagedTemplate")
			resp.SetTemplateName("Binding Managed Template")
			resp.SetFriendlyName("OldFriendlyName")
			resp.SetUseAllowedRequesters(false)
			resp.AllowedRequesters = nil
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode GET response: %v", err)
			}
		case r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			putBody = body
			var onWire map[string]interface{}
			_ = json.Unmarshal(body, &onWire)
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(11)
			resp.SetCommonName("BindingManagedTemplate")
			resp.SetTemplateName("Binding Managed Template")
			resp.SetFriendlyName("NewFriendlyName")
			// Echo AllowedRequesters back exactly as sent (full-replace
			// semantics): if the PUT omitted it, Command's real behavior is to
			// clear it server-side, so the response reflects empty too.
			if ar, ok := onWire["AllowedRequesters"].([]interface{}); ok {
				var roles []string
				for _, v := range ar {
					if s, ok := v.(string); ok {
						roles = append(roles, s)
					}
				}
				resp.AllowedRequesters = roles
				resp.SetUseAllowedRequesters(len(roles) > 0)
			} else {
				resp.AllowedRequesters = nil
				resp.SetUseAllowedRequesters(false)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode PUT response: %v", err)
			}
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	// Prior local state: absorbed RevokedRole from a previous Read (the
	// binding resource granted it out-of-band; this resource's own config
	// never declared it).
	state := blankTemplateState()
	state.ID = types.Int64{Value: 11}
	state.FriendlyName = types.String{Value: "OldFriendlyName"}
	state.UseAllowedRequesters = types.Bool{Value: true}
	state.AllowedRequesters = stringSliceToTfList([]string{"RevokedRole"})

	// Plan: friendly_name is newly declared (the "any other template
	// attribute changes" trigger), which is what makes the framework mark
	// allowed_requesters/use_allowed_requesters Unknown before
	// useStateOrNullModifier/UseStateForUnknown pin them back to the STALE
	// state value below -- reproduced by hand here since this test builds
	// plan directly rather than running PlanResourceChange.
	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 11}
	plan.FriendlyName = types.String{Value: "NewFriendlyName"}
	plan.UseAllowedRequesters = types.Bool{Value: true}
	plan.AllowedRequesters = stringSliceToTfList([]string{"RevokedRole"})

	// Config: allowed_requesters/use_allowed_requesters are NOT declared at
	// all (Null) -- this template's config manages them exclusively via
	// keyfactor_template_role_binding. friendly_name IS declared, matching
	// plan.
	config := blankTemplateState()
	config.ID = types.Int64{Value: 11}
	config.FriendlyName = types.String{Value: "NewFriendlyName"}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	// tfsdk.Config has no Set method (only Get/GetAttribute), so build the
	// desired config's raw tftypes.Value via a throwaway Plan of the same
	// schema and copy it over.
	tmpPlanForConfig := tfsdk.Plan{Schema: schema}
	if d := tmpPlanForConfig.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config Set (via throwaway Plan) returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: tmpPlanForConfig.Raw}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	if getHits != 1 {
		t.Fatalf("expected exactly 1 preservation GET, got %d", getHits)
	}
	if len(putBody) == 0 {
		t.Fatal("no PUT /Templates request was captured")
	}

	var onWire map[string]interface{}
	if err := json.Unmarshal(putBody, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}

	// The core assertion: RevokedRole must NOT be re-sent on the wire. Before
	// the fix, plan's non-null pinned ["RevokedRole"] value skipped the fresh
	// GET and this would fail.
	if ar, ok := onWire["AllowedRequesters"].([]interface{}); ok {
		for _, v := range ar {
			if v == "RevokedRole" {
				t.Fatalf(
					"AllowedRequesters on the wire = %v, contains RevokedRole -- this reproduces full-review "+
						"round 5's [HIGH] finding: Update() re-PUT a stale, binding-revoked role because it "+
						"keyed the preservation decision on plan null-ness instead of config declaredness. "+
						"Full payload: %s", ar, putBody,
				)
			}
		}
	}
	if v, ok := onWire["UseAllowedRequesters"]; ok && v == true {
		t.Fatalf(
			"UseAllowedRequesters on the wire = true, want false/omitted -- re-enabling requester restriction "+
				"alongside a resurrected role is the same silent re-grant. Full payload: %s", putBody,
		)
	}

	// The final applied state must also not carry RevokedRole forward.
	var finalState KeyfactorCertificateTemplateState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}
	if !finalState.AllowedRequesters.Null {
		var roles []string
		finalState.AllowedRequesters.ElementsAs(ctx, &roles, false)
		for _, role := range roles {
			if role == "RevokedRole" {
				t.Fatalf(
					"final state allowed_requesters = %v, contains RevokedRole -- the next Read would re-absorb "+
						"the silently re-granted role right back into state", roles,
				)
			}
		}
	}
}
