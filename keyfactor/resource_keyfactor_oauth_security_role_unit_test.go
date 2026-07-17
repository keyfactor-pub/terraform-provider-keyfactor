package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitOAuthSecurityRole_UpdateWarnsOnClaimMissingProvider is a regression
// test for the corruption risk in mapOAuthSecurityClaimsFromRole
// (keyfactor/helpers.go): when Command's GET /Security/Roles/{id} response
// includes a claim with no Provider sub-object, mapOAuthSecurityClaimsFromRole
// silently substituted an empty string for that claim's
// ProviderAuthenticationScheme. That value feeds directly into this resource's
// Update() at the NewUpdateSecurityRolesRequest call below -- an untested,
// full-replace PUT of the role's ENTIRE claims list. If Command omitted
// Provider due to a known server-side quirk (see the comment on
// mapOAuthSecurityClaimsFromRole, e.g. Command 25.5.1 + Authentik OIDC)
// rather than the claim genuinely having none, an unrelated Update to this
// role (e.g. changing only email_address) would silently reset that claim's
// provider association server-side.
//
// This drives the real Update() path end-to-end against a mock Command
// server whose GET /Security/Roles/{id} response includes one claim with
// Provider present and one with Provider omitted, and asserts:
//  1. Update() succeeds (does not error) but surfaces a warning diagnostic
//     naming the affected claim, instead of silently sending the empty
//     override.
//  2. The PUT /Security/Roles request body actually sent to Command reflects
//     what the fix can and cannot do: the well-formed claim's
//     ProviderAuthenticationScheme round-trips unchanged, while the
//     Provider-less claim's does go out as "" (the field is a plain
//     non-nullable string in the SDK request DTO, so there is no way to omit
//     it) -- proving the warning is necessary because the risk is real, not
//     eliminated.
func TestUnitOAuthSecurityRole_UpdateWarnsOnClaimMissingProvider(t *testing.T) {
	ctx := context.Background()

	const roleId int32 = 42

	var capturedPutBody []byte

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Security/Roles/%d", roleId), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"Id": %d,
			"Name": "tf-unit-oauth-role",
			"Description": "Unit test role",
			"EmailAddress": "role@example.com",
			"Immutable": false,
			"PermissionSetId": "11111111-1111-1111-1111-111111111111",
			"Permissions": ["Certificates:Read"],
			"Claims": [
				{
					"Id": 1,
					"Description": "claim with a provider",
					"ClaimType": "OAuthSubject",
					"ClaimValue": "well-formed-subject",
					"Provider": {"Id": "1", "AuthenticationScheme": "System", "DisplayName": "System"}
				},
				{
					"Id": 2,
					"Description": "claim Command omitted the provider for",
					"ClaimType": "OAuthSubject",
					"ClaimValue": "provider-less-subject",
					"Provider": null
				}
			]
		}`, roleId)))
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var err error
			capturedPutBody, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed reading PUT body: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"Id": %d,
			"Name": "tf-unit-oauth-role",
			"Description": "Unit test role updated",
			"EmailAddress": "role@example.com",
			"Immutable": false,
			"PermissionSetId": "11111111-1111-1111-1111-111111111111",
			"Permissions": ["Certificates:Read"],
			"Claims": []
		}`, roleId)))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	sdkClient := newOAuthRoleClaimAssocMockClient(server)

	schema, sDiags := resourceOAuthSecurityRoleType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := OAuthSecurityRole{
		ID:              types.Int64{Value: int64(roleId)},
		Name:            types.String{Value: "tf-unit-oauth-role"},
		Description:     types.String{Value: "Unit test role"},
		EmailAddress:    types.String{Value: "role@example.com"},
		Immutable:       types.Bool{Value: false},
		PermissionSetId: types.String{Value: "11111111-1111-1111-1111-111111111111"},
		Permissions: types.Set{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "Certificates:Read"},
		}},
	}

	// An unrelated field changes (description) -- claims are not managed by
	// this resource's config at all, so the plan is otherwise identical to
	// state.
	plan := state
	plan.Description = types.String{Value: "Unit test role updated"}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	r := resourceOAuthSecurityRole{p: provider{configured: true, sdkClient: sdkClient}}

	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostic errors: %+v", resp.Diagnostics)
	}

	foundWarning := false
	for _, d := range resp.Diagnostics.Warnings() {
		if d.Summary() == "OAuth security claim missing provider association" {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("expected a warning diagnostic flagging the claim with no Provider sub-object, got: %+v", resp.Diagnostics)
	}

	// Confirm what was actually sent to Command, so this test fails loudly if
	// a future change silently starts sending something worse (or if someone
	// removes the warning while believing the underlying risk was fixed).
	if len(capturedPutBody) == 0 {
		t.Fatal("expected the PUT /Security/Roles request body to have been captured")
	}
	var putReq struct {
		Claims []struct {
			ClaimValue                   string `json:"ClaimValue"`
			ProviderAuthenticationScheme string `json:"ProviderAuthenticationScheme"`
		} `json:"Claims"`
	}
	if err := json.Unmarshal(capturedPutBody, &putReq); err != nil {
		t.Fatalf("failed to unmarshal captured PUT body: %v; body: %s", err, string(capturedPutBody))
	}

	var wellFormedScheme, providerLessScheme string
	var sawWellFormed, sawProviderLess bool
	for _, c := range putReq.Claims {
		switch c.ClaimValue {
		case "well-formed-subject":
			wellFormedScheme = c.ProviderAuthenticationScheme
			sawWellFormed = true
		case "provider-less-subject":
			providerLessScheme = c.ProviderAuthenticationScheme
			sawProviderLess = true
		}
	}
	if !sawWellFormed || !sawProviderLess {
		t.Fatalf("expected both claims to round-trip into the PUT request, got: %+v", putReq.Claims)
	}
	assert.Equal(t, "System", wellFormedScheme, "the claim that DID have a Provider must round-trip its scheme unchanged")
	assert.Equal(t, "", providerLessScheme, "the claim that Command omitted Provider for is sent with an empty scheme (the SDK request field cannot be omitted) -- this is exactly the risk the warning diagnostic exists to flag")
}
