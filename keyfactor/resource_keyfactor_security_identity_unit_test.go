package keyfactor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitSecurityIdentityRolesDeclared is a regression test for the bug where
// Update() always ran setIdentityRole (a full-replace sync of the identity's
// role assignments), even when the roles attribute was simply omitted from
// config (Null). That conflated "roles undeclared" with "roles explicitly
// emptied" and stripped every real role assignment on any unrelated Update.
//
// roles is Optional (not Computed): a Null value means preserve existing
// assignments (do not sync), while a non-null value — including an explicit
// empty list — is a full-replace instruction (an empty list clears all roles).
func TestUnitSecurityIdentityRolesDeclared(t *testing.T) {
	cases := []struct {
		name        string
		roles       types.List
		wantReplace bool
		reason      string
	}{
		{
			name:        "roles undeclared (null) -> preserve",
			roles:       types.List{Null: true, ElemType: types.StringType},
			wantReplace: false,
			reason:      "an undeclared roles attribute must preserve existing assignments, not full-replace",
		},
		{
			name:        "roles unknown -> preserve",
			roles:       types.List{Unknown: true, ElemType: types.StringType},
			wantReplace: false,
			reason:      "an unknown roles value must not trigger a destructive full-replace",
		},
		{
			name:        "roles explicitly empty -> clear",
			roles:       types.List{ElemType: types.StringType, Elems: []attr.Value{}},
			wantReplace: true,
			reason:      "an explicit empty list must still full-replace (clearing all roles)",
		},
		{
			name: "roles populated -> replace",
			roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
				types.String{Value: "Administrator"},
			}},
			wantReplace: true,
			reason:      "a populated roles list must full-replace",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := SecurityIdentity{Roles: tc.roles}
			assert.Equal(t, tc.wantReplace, identityRolesDeclared(plan), tc.reason)
		})
	}
}

// TestUnitSecurityIdentityRead_DetectsOutOfBandRoleDrift is a regression test
// for Read() rebuilding the `roles` state by re-validating the identity's
// PRIOR state (state.Roles.Elems) instead of using the freshly-fetched
// identity.Roles from the GetSecurityIdentities() response. That meant real
// server-side role drift (someone changed roles out-of-band, outside
// Terraform) was never detected — Read() just echoed back whatever was
// already in state.
//
// This test mocks GetSecurityIdentities() to return an identity whose roles
// (["RoleB"]) differ from prior state (["RoleA"]), and asserts Read() writes
// the freshly-fetched value into state, not the stale one.
func TestUnitSecurityIdentityRead_DetectsOutOfBandRoleDrift(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Identities", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"Id":           42,
				"AccountName":  "KEYFACTOR\\\\tf-unit-drift",
				"IdentityType": "User",
				"Valid":        true,
				"Roles": []map[string]interface{}{
					{"Id": 2, "Name": "RoleB"},
				},
			},
		})
	})
	// Only exercised by the unfixed code, which re-validates prior-state roles
	// via GetSecurityRole before trusting them.
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Id": 1, "Name": "RoleA", "Description": ""},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-drift`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "RoleA"},
		}},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &priorState); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceSecurityIdentity{p: provider{configured: true, client: client}}

	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result SecurityIdentity
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	var roles []string
	for _, e := range result.Roles.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected roles element to be types.String, got %T", e)
		}
		roles = append(roles, s.Value)
	}

	assert.Equal(t, []string{"RoleB"}, roles, "Read() must reflect the freshly-fetched server roles, not the stale prior-state roles")
}
