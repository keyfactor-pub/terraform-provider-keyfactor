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
