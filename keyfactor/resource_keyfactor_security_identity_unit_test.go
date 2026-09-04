package keyfactor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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

// TestUnitSecurityIdentitySchema_RolesIsComputedWithUseStateForUnknown is a
// regression test for "Provider produced inconsistent result after apply:
// .roles: was null, but now cty.ListVal(...)".
//
// roles was Optional but NOT Computed. Update() (see identityRolesDeclared)
// deliberately writes state.Roles (a concrete, non-null list) into the result
// whenever the config omits roles, to preserve the identity's existing role
// assignments across an unrelated Update. But for a non-Computed attribute,
// Terraform Core computes the practitioner-facing plan directly from config:
// omitted config -> planned value is Null, full stop, with no path for a
// provider-side plan modifier to intervene. When Update() then returned a
// non-null Roles, Core saw the final value diverge from what it planned and
// aborted the apply with "inconsistent result after apply" on any identity
// that already had roles assigned.
//
// Why this shipped: this repo's TestUnit* harness (see
// TestUnitSecurityIdentityRead_DetectsOutOfBandRoleDrift above) calls
// resourceSecurityIdentity's methods directly via hand-built tfsdk.Plan/
// tfsdk.State values -- it never drives a real Terraform Core plan/apply
// cycle (that would require github.com/hashicorp/terraform-plugin-testing,
// which is not a dependency of this module and is blocked on this repo's
// terraform-plugin-framework v0.10.0 pin). Because of that, Update()'s
// returned value looked entirely correct in isolation (it does preserve the
// right roles) -- the defect is only visible one layer up, in how Terraform
// Core reconciles the schema-declared plan against that returned value. The
// strongest regression test achievable without a full Core harness is
// asserting the schema fix directly, mirroring
// TestUnitTemplateSchema_V25CleanupFieldsUseStateForUnknown's approach for
// the same bug class on a different resource: roles must be Optional+Computed
// with a UseStateForUnknown plan modifier, so Core resolves the omitted-roles
// case to "carry forward the prior state value" instead of "plan Null."
func TestUnitSecurityIdentitySchema_RolesIsComputedWithUseStateForUnknown(t *testing.T) {
	ctx := context.Background()

	schema, diags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", diags)
	}

	attribute, ok := schema.Attributes["roles"]
	if !ok {
		t.Fatalf("expected schema attribute %q to exist", "roles")
	}

	if !attribute.Optional || !attribute.Computed {
		t.Fatalf("attribute %q: expected Optional+Computed, got Optional=%v Computed=%v", "roles", attribute.Optional, attribute.Computed)
	}

	found := false
	for _, m := range attribute.PlanModifiers {
		if _, ok := m.(tfsdk.UseStateForUnknownModifier); ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("attribute %q: expected UseStateForUnknown plan modifier so an omitted-from-config value carries forward from state instead of planning Null, but none was found (modifiers: %+v)", "roles", attribute.PlanModifiers)
	}
}

// TestUnitSecurityIdentityResource_UpdatePreservesRolesWhenConfigOmitsThem is a
// functional companion to the schema-level test above: it exercises the real
// Update() path with a Config that omits roles (Null) but a Plan that already
// carries the prior state's roles forward -- reproducing exactly what
// UseStateForUnknownModifier hands Update() once the schema fix from
// TestUnitSecurityIdentitySchema_RolesIsComputedWithUseStateForUnknown is in
// place (see UseStateForUnknownModifier.Modify in
// vendor/.../tfsdk/attribute_plan_modification.go: it copies AttributeState
// into AttributePlan when AttributeConfig is null and AttributePlan is
// unknown). It asserts Update()'s returned Roles is IDENTICAL to the planned
// value, which is the actual invariant Terraform Core enforces ("the final
// value of a Known planned attribute must not change") -- not just "close
// enough" or "the right role names in some form."
func TestUnitSecurityIdentityResource_UpdatePreservesRolesWhenConfigOmitsThem(t *testing.T) {
	ctx := context.Background()

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorRoles := types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "Administrator"},
	}}

	state := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: "KEYFACTOR\\\\tf-unit-preserve"},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles:        priorRoles,
	}

	// The plan is what UseStateForUnknownModifier produces: the prior state's
	// roles copied forward because config is null and the raw plan was
	// unknown. Every other field mirrors an unrelated attribute change (a
	// realistic "unrelated Update").
	plan := state

	// The config is what the practitioner actually wrote: roles is genuinely
	// absent (Null), which is what makes this the undeclared case rather than
	// an explicit re-declaration of the same list.
	config := SecurityIdentity{
		ID:           state.ID,
		AccountName:  state.AccountName,
		IdentityType: state.IdentityType,
		Valid:        state.Valid,
		Roles:        types.List{Null: true, ElemType: types.StringType},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	// tfsdk.Config has no Set method of its own; build its Raw value the same
	// way Plan/State do and reuse it, since Config/Plan/State all wrap an
	// identically-shaped (Raw tftypes.Value, Schema tfsdk.Schema) pair.
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityIdentity{p: provider{configured: true, client: nil}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var result SecurityIdentity
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}

	var gotRoles []string
	for _, e := range result.Roles.Elems {
		s, ok := e.(types.String)
		if !ok {
			t.Fatalf("expected roles element to be types.String, got %T", e)
		}
		gotRoles = append(gotRoles, s.Value)
	}

	assert.Equal(
		t, []string{"Administrator"}, gotRoles,
		"Update() must write exactly the planned roles into state when config omits the attribute -- Terraform Core already committed to this planned value, so any divergence is an inconsistent-result-after-apply error",
	)
}

// TestUnitSecurityIdentityReadKeepsDeclaredRoleSpelling is a regression test
// for F173-2: Read() rebuilt `roles` unconditionally from the server's
// canonical role names (identity.Roles), even when the server's role set was
// semantically identical to what the user declared -- just spelled
// differently (case) or in a different but equivalent form (numeric ID vs.
// name, see the companion ID test below). That rewrote a practitioner's
// declared lowercase role name to Command's canonical capitalization on every
// Read, manufacturing a permanent diff no `terraform apply` could ever
// resolve.
//
// This drives Read() end-to-end against a mock Command server whose identity
// has a single role named "Administrators", with prior state declaring the
// same role as lowercase "administrators", and asserts Read() preserves the
// user's declared spelling rather than overwriting it with the server's
// canonical form.
func TestUnitSecurityIdentityReadKeepsDeclaredRoleSpelling(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc(
		"/KeyfactorAPI/Security/Identities", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(
				[]map[string]interface{}{
					{
						"Id":           42,
						"AccountName":  "KEYFACTOR\\\\tf-unit-spelling",
						"IdentityType": "User",
						"Valid":        true,
						"Roles": []map[string]interface{}{
							{"Id": 5, "Name": "Administrators"},
						},
					},
				},
			)
		},
	)
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-spelling`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "administrators"},
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

	assert.Equal(
		t, []string{"administrators"}, roles,
		"Read() must keep the declared role spelling when it is semantically the same role as the server reports, not overwrite it with the server's canonical capitalization",
	)
}

// TestUnitSecurityIdentityReadNumericIdMatchesServerRole is a companion
// regression test for F173-2: prior state may declare a role by its numeric
// Command role ID rather than name (the roles attribute schema description
// documents both forms are accepted). Read() must recognize that
// declaration as the same role when the server reports it by name, and
// preserve the declared numeric-ID form rather than rewriting it to the
// server's name.
func TestUnitSecurityIdentityReadNumericIdMatchesServerRole(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc(
		"/KeyfactorAPI/Security/Identities", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(
				[]map[string]interface{}{
					{
						"Id":           42,
						"AccountName":  "KEYFACTOR\\\\tf-unit-id",
						"IdentityType": "User",
						"Valid":        true,
						"Roles": []map[string]interface{}{
							{"Id": 5, "Name": "Administrators"},
						},
					},
				},
			)
		},
	)
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-id`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "5"},
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

	assert.Equal(
		t, []string{"5"}, roles,
		"Read() must keep the declared numeric role ID when it matches the server's role by ID, not overwrite it with the server's role name",
	)
}

// TestUnitSecurityIdentityResource_UpdateFailsOnRoleLookupError is a
// regression test for Update() treating a role lookup error (or a (nil, nil)
// "not found" GetSecurityRole response) as a Warning-and-continue: dropping
// the unresolvable role from validRolesInterface let setIdentityRole's
// full-replace sync run anyway, actively REVOKING the identity's existing
// membership in that role while the apply exited 0 and state recorded the
// full plan.Roles as assigned -- a silent access change contradicting the
// executed action.
//
// This drives Update() end-to-end against a mock Command server whose role
// name lookup (GET /Security/Roles?pq.queryString=...) fails with HTTP 500,
// and asserts (1) Update() surfaces an error diagnostic, and (2) no
// role-mutation call (PUT /Security/Roles, which setIdentityRole's
// addIdentityToRole/removeIdentityFromRole would issue) is ever made --
// the apply must fail with nothing mutated, not partially apply then error.
func TestUnitSecurityIdentityResource_UpdateFailsOnRoleLookupError(t *testing.T) {
	ctx := context.Background()

	var mutationCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutationCalled = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Id": 7, "Name": "Power Users"})
			return
		}
		// The name-lookup GET fails transiently -- e.g. a network blip or
		// server error, not a genuine "role doesn't exist".
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Internal Server Error"})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-lookup-fail`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "Administrators"},
		}},
	}

	// Plan/config declare a new role, forcing the lookup that fails.
	plan := state
	plan.Roles = types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "Power Users"},
	}}
	config := plan

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityIdentity{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	assert.True(t, resp.Diagnostics.HasError(),
		"Update() must fail the apply when a declared role's lookup errors, not silently drop the role and proceed with a partial role sync")
	assert.False(t, mutationCalled,
		"Update() must not call setIdentityRole (any role add/remove) when a declared role's lookup failed -- doing so would revoke the identity's existing role membership under a state record that claims success")
}

// TestUnitSecurityIdentityResource_UpdateRoleLookupPreservesSpaces is a
// regression test for the `[^\w]` sanitizer applied to role.String() (the
// framework's %q-quoted representation) before the role name lookup: for a
// role name containing a space or hyphen (e.g. "Power Users"), the sanitizer
// stripped more than just the surrounding quotes, mangling the lookup to
// "PowerUsers" -- a role that doesn't exist. That caused a (nil, nil)
// "not found" response and, pre-fix, silently dropped the role and revoked
// the identity's real membership in "Power Users" on every apply.
//
// This drives Update() end-to-end and captures the actual HTTP query string
// GetSecurityRole issues, asserting the role name reaches the server
// unmangled -- spaces intact -- rather than as a sanitizer-stripped
// alphanumeric string.
func TestUnitSecurityIdentityResource_UpdateRoleLookupPreservesSpaces(t *testing.T) {
	ctx := context.Background()

	var capturedQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			capturedQuery = r.URL.Query().Get("pq.queryString")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"Id": 7, "Name": "Power Users", "Description": ""},
			})
			return
		}
		t.Fatalf("unexpected %s request to /KeyfactorAPI/Security/Roles -- the identity is already a member of the role, so no role mutation should be needed", r.Method)
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/7", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// The identity is already associated with the role, so
		// addIdentityToRole short-circuits without issuing a PUT.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id":   7,
			"Name": "Power Users",
			"Identities": []map[string]interface{}{
				{"AccountName": `KEYFACTOR\\tf-unit-space`},
			},
		})
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Identities", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"Id":           42,
				"AccountName":  `KEYFACTOR\\tf-unit-space`,
				"IdentityType": "User",
				"Valid":        true,
				"Roles": []map[string]interface{}{
					{"Id": 7, "Name": "Power Users"},
				},
			},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-space`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles:        types.List{ElemType: types.StringType, Elems: []attr.Value{}},
	}

	plan := state
	plan.Roles = types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "Power Users"},
	}}
	config := plan

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityIdentity{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	assert.Equal(
		t, `name -eq "Power Users"`, capturedQuery,
		"the role lookup query must carry the role name's raw value, unmangled by the old `[^\\w]` sanitizer over role.String() which stripped spaces (and would have looked up \"PowerUsers\" instead)",
	)
}

// TestUnitRoleLookupLogMessageEscapesControlCharacters is a regression test
// for a CWE-117 (log injection) finding: the tflog.Debug message logged
// before looking up a declared `roles` entry used to be built with
// `fmt.Sprintf("Looking up role %v in Keyfactor", roleStr)`. roleStr is a
// declared config value, and %v does no escaping of embedded control
// characters -- hclog's plain-text writer emits the resulting message
// verbatim -- so a role string containing an embedded "\r\n" could forge
// what looks like a second, fake log line under TF_LOG=DEBUG/TRACE.
// Previously, the logged value was always the framework's %q-quoted
// role.String() form, which escapes exactly this.
//
// roleLookupLogMessage is the extracted helper both Update()'s and Create()'s
// role-lookup loops now call, using %q instead of %v. This drives the actual
// helper (not a reimplementation of the format string) with a role string
// containing an embedded CRLF sequence and asserts the result is a single,
// escaped line: no raw "\r" or "\n" byte reaches the message, and the
// original control characters are recoverable only via their escaped (%q)
// form.
func TestUnitRoleLookupLogMessageEscapesControlCharacters(t *testing.T) {
	const injected = "Administrators\r\nlevel=error msg=\"fake injected log line\""

	got := roleLookupLogMessage(injected)

	assert.NotContains(t, got, "\r", "the log message must not contain a raw carriage return -- an unescaped CR/LF could be used to forge a fake log line")
	assert.NotContains(t, got, "\n", "the log message must not contain a raw newline -- an unescaped CR/LF could be used to forge a fake log line")
	assert.Equal(
		t, `Looking up role "Administrators\r\nlevel=error msg=\"fake injected log line\"" in Keyfactor`, got,
		"roleLookupLogMessage must %q-quote roleStr so embedded control characters are escaped, not interpolate it raw via %v/%s",
	)
}

// TestUnitRoleIdToInt is a regression test for setIdentityRole's role-ID type
// switch, which blindly asserted every non-int role identifier to int via a
// `case string, interface{}: roleId = role.(int)` catch-all. Since
// api.GetSecurityRoleResponse.Id (github.com/Keyfactor/keyfactor-go-client/v3
// /api/security_models.go) is declared as float64 -- both the by-name and
// by-ID GetSecurityRole lookup branches populate it that way -- every role ID
// Create()/Update() appended to validRolesInterface was actually a float64,
// never an int. The old switch's `interface{}` case matched float64 and then
// panicked on the hard `.(int)` assertion, meaning ANY successful role
// resolution during a real Create or Update would crash `terraform apply`
// (see TestUnitSecurityIdentityResource_UpdateRoleLookupPreservesSpaces
// below, which reproduces this end-to-end).
//
// roleIdToInt replaces that switch: it accepts int (defensive) and float64
// (the real-world case), and returns an error -- never panics -- for any
// other type.
func TestUnitRoleIdToInt(t *testing.T) {
	cases := []struct {
		name    string
		in      interface{}
		want    int
		wantErr bool
	}{
		{name: "int passes through", in: int(7), want: 7},
		{name: "float64 converts (the real-world case from api.GetSecurityRoleResponse.Id)", in: float64(7), want: 7},
		{name: "unexpected type errors instead of panicking", in: "7", wantErr: true},
		{name: "nil errors instead of panicking", in: nil, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := roleIdToInt(tc.in)
			if tc.wantErr {
				assert.Error(t, err, "an unexpected role identifier type must produce an error, not a panic")
				return
			}
			if assert.NoError(t, err) {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// TestUnitSetIdentityRole_UnexpectedRoleIdTypeErrors is the setIdentityRole-
// level companion to TestUnitRoleIdToInt: it drives the real function (not
// just the roleIdToInt helper) with a role ID of an unexpected type, and
// asserts setIdentityRole returns an error instead of panicking, and that no
// HTTP request is ever issued (the bad value is caught before any network
// call).
func TestUnitSetIdentityRole_UnexpectedRoleIdTypeErrors(t *testing.T) {
	ctx := context.Background()

	requestMade := false
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestMade = true
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	err := setIdentityRole(ctx, client, "tf-unit-badtype", []interface{}{"not-a-number"})

	assert.Error(t, err, "setIdentityRole must return an error for an unexpected role identifier type, not panic")
	assert.False(t, requestMade, "setIdentityRole must reject the bad role identifier before issuing any HTTP request")
}

// TestUnitSecurityIdentityReadSurfacesRealDrift is the negative-case
// companion to the two tests above: when the server's role set genuinely
// differs from what's declared (an extra role attached out-of-band), Read()
// must still surface that as drift by writing the server's canonical role
// names, not mask it under the "preserve declared spelling" behavior added
// for F173-2.
func TestUnitSecurityIdentityReadSurfacesRealDrift(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc(
		"/KeyfactorAPI/Security/Identities", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(
				[]map[string]interface{}{
					{
						"Id":           42,
						"AccountName":  "KEYFACTOR\\\\tf-unit-realdrift",
						"IdentityType": "User",
						"Valid":        true,
						"Roles": []map[string]interface{}{
							{"Id": 5, "Name": "Administrators"},
							{"Id": 6, "Name": "Auditors"},
						},
					},
				},
			)
		},
	)
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	priorState := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-realdrift`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "administrators"},
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

	assert.Equal(
		t, []string{"Administrators", "Auditors"}, roles,
		"Read() must surface real out-of-band role drift with the server's canonical names, not hide it behind declared-spelling preservation",
	)
}

// TestUnitSecurityIdentityResource_CreateFailsOnRoleLookupError is a
// regression test for Create() treating a role lookup error (or a (nil, nil)
// "not found" GetSecurityRole response) as an AddWarning-and-continue: the
// unresolvable role was silently dropped from validRolesInterface (so
// setIdentityRole, when called, never actually granted it), yet the separate
// `validRoles` bookkeeping list this dropping fed into was never even used --
// the final state write used the full, undropped `plan.Roles` regardless, so
// state (and a green `terraform apply`) claimed every declared role was
// granted even when one silently wasn't.
//
// The fix makes Create() fail-fast on any role lookup error or not-found for a
// declared role, exactly mirroring Update()'s fix -- AddError instead
// of AddWarning, and return before ever calling setIdentityRole. Unlike
// Update(), the identity has ALREADY been created on Keyfactor by the time
// the role loop runs, so this test also asserts the resulting state: the
// already-created identity must still be persisted (tracked, not orphaned
// out of state), but with Roles reflecting reality -- empty, since nothing
// was actually granted -- rather than the full declared plan.Roles.
func TestUnitSecurityIdentityResource_CreateFailsOnRoleLookupError(t *testing.T) {
	ctx := context.Background()

	var mutationCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Identities", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Id":           99,
				"AccountName":  `KEYFACTOR\\tf-unit-create-lookup-fail`,
				"IdentityType": "User",
				"Valid":        true,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutationCalled = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Id": 7, "Name": "Administrators"})
			return
		}
		// The name-lookup GET fails transiently -- e.g. a network blip or
		// server error, not a genuine "role doesn't exist".
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Internal Server Error"})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	plan := SecurityIdentity{
		AccountName: types.String{Value: `KEYFACTOR\\tf-unit-create-lookup-fail`},
		Roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
			types.String{Value: "Administrators"},
		}},
	}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	r := resourceSecurityIdentity{p: provider{configured: true, client: client}}

	req := tfsdk.CreateResourceRequest{Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Create(ctx, req, resp)

	assert.True(
		t, resp.Diagnostics.HasError(),
		"Create() must fail the apply when a declared role's lookup errors, not silently drop the role via AddWarning and report success",
	)
	assert.False(
		t, mutationCalled,
		"Create() must not call setIdentityRole (any role add/remove) when a declared role's lookup failed",
	)

	var result SecurityIdentity
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}
	assert.Equal(
		t, int64(99), result.ID.Value,
		"the identity was already created on Keyfactor before the role lookup failed; it must still be tracked in state, not orphaned",
	)
	assert.Empty(
		t, result.Roles.Elems,
		"Roles must reflect that nothing was actually granted (setIdentityRole was never called), not the full declared plan.Roles",
	)
}

// TestUnitSecurityIdentityResource_UpdateFailsWhenNumericRoleMatchesNeitherIdNorName
// is a regression test proving the not-found case is unchanged from this
// resource's behavior for a declared role string that resolves neither by ID
// nor by name: a numeric roles entry like "7" that matches no role with ID 7
// AND no role literally named "7" must still fail cleanly, with no warning
// diagnostic (the ID-path warning is only emitted when the ID lookup itself
// actually resolves a role -- see
// TestUnitSecurityIdentityResource_ResolveDeclaredSecurityRoleIdPathResolvesWithWarning
// below for that case).
//
// This drives Update() end-to-end with roles = ["7"] against a mock server
// where neither the ID-path endpoint (GET /Security/Roles/7, tried first)
// nor the name-query fallback resolves a role.
func TestUnitSecurityIdentityResource_UpdateFailsWhenNumericRoleMatchesNeitherIdNorName(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/7", func(w http.ResponseWriter, r *http.Request) {
		// No role has ID 7 either.
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Not Found"})
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected %s request to /KeyfactorAPI/Security/Roles -- role lookup for \"7\" must fail (no role is literally named \"7\" and no role has ID 7), so no mutation should ever be attempted", r.Method)
		}
		// No role is literally named "7".
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Identities", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"Id":           42,
				"AccountName":  `KEYFACTOR\\tf-unit-numeric-id`,
				"IdentityType": "User",
				"Valid":        true,
				"Roles":        []map[string]interface{}{},
			},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-numeric-id`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles:        types.List{ElemType: types.StringType, Elems: []attr.Value{}},
	}

	plan := state
	plan.Roles = types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "7"},
	}}
	config := plan

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityIdentity{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	assert.True(
		t, resp.Diagnostics.HasError(),
		"Update() must fail the apply: a numeric roles entry like \"7\" that matches no role by name and no role by ID must still be reported as not found",
	)
	assert.Empty(
		t, resp.Diagnostics.Warnings(),
		"no ID-fallback warning should be emitted when the ID fallback itself did not resolve a role",
	)
}

// TestUnitSecurityIdentityResource_ResolveDeclaredSecurityRoleIdPathResolvesWithWarning
// is a regression test for the ID-first design: a declared numeric string
// (e.g. "7") is tried via the ID-path lookup (GET /Security/Roles/{id})
// FIRST -- a parseable-int string is more likely intended as a role ID than
// a literal role name, and the schema has always documented "role IDs" as an
// accepted form. When that ID lookup resolves a real role,
// resolveDeclaredSecurityRole must return it AND unconditionally emit a
// warning diagnostic -- this is the specific, previously-impossible outcome
// this change enables: a declared numeric string that used to always fail to
// resolve (every prior release only ever looked up roles by name) can now
// silently start granting a real, possibly highly-privileged role on nothing
// more than a routine provider upgrade, purely because Command happens to
// have a role with that literal numeric ID. The warning surfaces that in
// `terraform plan`/`apply` output.
//
// This drives resolveDeclaredSecurityRole directly against a mock server
// that never registers the name-query endpoint at all: if a regression
// caused the name-based lookup to be tried instead of (or before) the
// ID-path lookup, hitting that unregistered endpoint would surface as a
// response-decode error, failing the assertions below -- catching a
// regression to name-first ordering.
func TestUnitSecurityIdentityResource_ResolveDeclaredSecurityRoleIdPathResolvesWithWarning(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/7", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Id": 7, "Name": "RoleSeven", "Description": "the real role with ID 7",
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	var diags diag.Diagnostics
	kfRole, err := resolveDeclaredSecurityRole(client, "7", &diags)
	if !assert.NoError(t, err, "the ID-path lookup must resolve role ID 7 without needing a name-based fallback") {
		return
	}
	if !assert.NotNil(t, kfRole, "resolveDeclaredSecurityRole must not return a nil role when the ID lookup found a genuine match") {
		return
	}
	assert.Equal(t, float64(7), kfRole.Id,
		"resolveDeclaredSecurityRole must resolve to the role's real ID (7) via the ID-path lookup")

	if !assert.Len(t, diags.Warnings(), 1,
		"resolving via the ID-path lookup must always emit exactly one warning diagnostic, since it can silently grant a role an existing customer's config previously never resolved") {
		return
	}
	warning := diags.Warnings()[0]
	assert.Contains(t, warning.Detail(), "7",
		"the warning must identify the declared value that triggered the ID-path resolution")
	assert.Contains(t, strings.ToLower(warning.Summary()+" "+warning.Detail()), "numeric",
		"the warning should make clear the match happened via a numeric ID, not a name match")
}

// TestUnitSecurityIdentityResource_ResolveDeclaredSecurityRoleNumericNameFallbackNoWarning
// is a regression test for the one pre-existing case the ID-first design
// must not regress: a security role whose display Name is itself a purely
// numeric string (e.g. a role literally named "123") resolved correctly by
// name before any numeric-ID resolution existed. Since the ID-path lookup is
// now tried first for a numeric declaration, that role's real ID (distinct
// from its Name) may not exist / may not match -- this asserts that when the
// ID lookup fails (404/not-found), resolveDeclaredSecurityRole falls back to
// the name-based lookup, resolves the role literally named "123", and emits
// NO warning, since name-based resolution of a numeric string was already
// possible pre-this-PR and is not new, surprising behavior.
func TestUnitSecurityIdentityResource_ResolveDeclaredSecurityRoleNumericNameFallbackNoWarning(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/123", func(w http.ResponseWriter, r *http.Request) {
		// No role has ID 123.
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Not Found"})
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		// A role literally named "123" does exist, with a different real ID
		// (7), reached via the name-based fallback.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Id": 7, "Name": "123", "Description": "a role literally named 123"},
		})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	var diags diag.Diagnostics
	kfRole, err := resolveDeclaredSecurityRole(client, "123", &diags)
	if !assert.NoError(t, err, "the name-based fallback must resolve a role literally named \"123\" once the ID lookup fails") {
		return
	}
	if !assert.NotNil(t, kfRole, "resolveDeclaredSecurityRole must not return a nil role when the name fallback found a genuine match") {
		return
	}
	assert.Equal(t, float64(7), kfRole.Id,
		"resolveDeclaredSecurityRole must resolve to the role's real ID (7) via the name fallback, not fail just because ID 123 doesn't exist")
	assert.Empty(t, diags.Warnings(),
		"no warning should be emitted for the name-based fallback -- resolving a numeric string by name was already possible and is not new, surprising behavior")
}

// TestUnitSecurityIdentityResource_UpdateRejectsUnverifiedRoleNameMatch is a
// regression test for Fix C: GetSecurityRole's string branch builds
// `name -eq "<value>"` PQL with zero escaping of the declared role string
// (keyfactor-go-client v3/api/security.go). A pre-existing `[^\w]` sanitizer
// used to strip quotes and PQL operators from the role string before lookup,
// accidentally closing off query injection; it was removed (correctly, to
// stop mangling legitimate names like "Power Users") but nothing replaced
// the safeguard it happened to provide.
//
// This simulates a successful injection: the declared role string is a
// PQL-operator-shaped payload containing an embedded `"`, and the mock
// server's name-query handler returns an entirely unrelated role
// ("Administrators") rather than erroring or reporting "not found" -- as
// Command's query parser might do if it honors an injected `-or` clause.
// resolveDeclaredSecurityRole must reject this as unresolved (the returned
// role's Name doesn't match the declared string) rather than trusting the
// query match, so Update() surfaces an error and never calls setIdentityRole
// with the unrelated role's ID.
func TestUnitSecurityIdentityResource_UpdateRejectsUnverifiedRoleNameMatch(t *testing.T) {
	ctx := context.Background()

	const injectionPayload = `Foo" -or name -eq "Administrators`

	var mutationCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutationCalled = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"Id": 1, "Name": "Administrators"})
			return
		}
		// Simulate a successful injection: the query for the payload string
		// returns an unrelated, genuinely-existing role instead of erroring
		// or coming back empty.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Id": 1, "Name": "Administrators", "Description": ""},
		})
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutationCalled = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Description must be non-blank: UpdateSecurityRole (called by
		// addIdentityToRole) rejects a blank Description with a client-side
		// validation error before ever issuing the PUT. Without a non-blank
		// Description here, setIdentityRole would error out for that
		// unrelated reason even on the UNFIXED code, masking whether Fix C's
		// name-match check is actually what's preventing the mutation.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Id": 1, "Name": "Administrators", "Description": "Built-in administrators role"})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-injection`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles:        types.List{ElemType: types.StringType, Elems: []attr.Value{}},
	}

	plan := state
	plan.Roles = types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: injectionPayload},
	}}
	config := plan

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityIdentity{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	assert.True(
		t, resp.Diagnostics.HasError(),
		"Update() must reject a name-query match whose returned role Name doesn't match the declared string -- an unverified match must not be trusted, even if Command's query parser honored an injected clause",
	)
	assert.False(
		t, mutationCalled,
		"Update() must not call setIdentityRole (any role add/remove) when the declared role's lookup could not be verified",
	)
}

// TestUnitSecurityIdentityResource_UpdateSetIdentityRoleFailurePersistsState is
// a regression test for Fix D: Update()'s setIdentityRole failure branch
// returned without ever calling response.State.Set. setIdentityRole is NOT
// atomic -- it issues one Command API call per role addition, then one per
// role removal -- so a failure partway through can leave Command's actual
// role membership already diverged from both the prior state and the plan.
// Returning without an explicit State.Set relied entirely on the framework's
// implicit "persist req.PriorState" default (see
// vendor/github.com/hashicorp/terraform-plugin-framework/internal/fwserver/
// server_updateresource.go), which is *safe* in production (Terraform Core
// pre-seeds it) but, in this repo's direct-method-call unit test harness,
// means resp.State is left as a completely unset zero value -- and even in
// production, the diagnostic never told the operator that a partial mutation
// might have occurred.
//
// This drives Update() with a role addition whose underlying PUT (issued by
// addIdentityToRole, invoked from setIdentityRole) fails with HTTP 500, and
// asserts: (1) an error diagnostic is produced, (2) the diagnostic text warns
// about a possible partial change and tells the operator to re-plan, and (3)
// resp.State was explicitly populated (Raw is not the null zero-value, and
// reading it back succeeds and reflects the untouched prior state).
func TestUnitSecurityIdentityResource_UpdateSetIdentityRoleFailurePersistsState(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"Id": 1, "Name": "RoleA", "Description": "desc"},
		})
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles/1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Id":          1,
				"Name":        "RoleA",
				"Identities":  []map[string]interface{}{},
				"Description": "desc",
			})
			return
		}
		// The PUT that addIdentityToRole issues to actually grant the role
		// fails -- simulating a mutation that errors partway through
		// setIdentityRole's sequential add-loop.
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Internal Server Error"})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	schema, sDiags := resourceSecurityIdentityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := SecurityIdentity{
		ID:           types.Int64{Value: 42},
		AccountName:  types.String{Value: `KEYFACTOR\\tf-unit-setrole-fail`},
		IdentityType: types.String{Value: "User"},
		Valid:        types.Bool{Value: true},
		Roles:        types.List{ElemType: types.StringType, Elems: []attr.Value{}},
	}

	plan := state
	plan.Roles = types.List{ElemType: types.StringType, Elems: []attr.Value{
		types.String{Value: "RoleA"},
	}}
	config := plan

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceSecurityIdentity{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	assert.True(t, resp.Diagnostics.HasError(),
		"Update() must surface an error when setIdentityRole fails")

	foundPartialWarning := false
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Detail(), "partially") && strings.Contains(d.Detail(), "terraform plan") {
			foundPartialWarning = true
		}
	}
	assert.True(t, foundPartialWarning,
		"the error diagnostic must mention that role membership may have been partially changed on Keyfactor Command and that `terraform plan` will detect/reconcile any actual drift, not just report a bare error")

	assert.False(t, resp.State.Raw.IsNull(),
		"Update() must explicitly persist state on the setIdentityRole failure path, not leave resp.State completely unset")

	var result SecurityIdentity
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("resp.State was not populated with a value conforming to the schema: %+v", d)
	}
	assert.Equal(t, state.AccountName.Value, result.AccountName.Value,
		"the persisted state must reflect the untouched prior AccountName")
	assert.Empty(t, result.Roles.Elems,
		"the persisted state must reflect the untouched prior Roles (empty), not the plan's Roles that may not have actually been granted")
}

// Note: the numeric-string-resolves-by-name-fallback scenario (a role
// literally named "123") is covered by
// TestUnitSecurityIdentityResource_ResolveDeclaredSecurityRoleNumericNameFallbackNoWarning
// above, which also asserts no warning is emitted for that fallback path.
