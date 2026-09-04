package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- full-review findings F2/F4:
//
// associated_roles/certificate_authorities (F2) and
// policies.default_certificate_owner_role_name (F4) are read-only mirrors
// that the server expands from a write-only "driver" attribute
// (associated_role_names/certificate_authority_ids/
// policies.default_certificate_owner_role_id respectively). All three used
// tfsdk.UseStateForUnknown()-style modifiers (useStateOrNullModifier /
// tfsdk.UseStateForUnknown()) that unconditionally pin the mirror to its
// PRIOR state value whenever the mirror's own plan is Unknown -- including
// when the driver attribute is CHANGING this apply. Since Update() writes
// the genuinely new, response-derived membership/name into the final state,
// the pinned (stale) planned value and the applied (fresh) value disagree,
// and Terraform Core hard-errors with "Provider produced inconsistent
// result after apply" on this resource's ordinary, primary update path
// (e.g. editing associated_role_names or
// policies.default_certificate_owner_role_id) -- not an edge case.
//
// followsDriverModifier[T] fixes this by only pinning the mirror to prior
// state when the driver is NOT changing (undeclared, or re-declared with
// its current value); otherwise it leaves the mirror Unknown so Update()'s
// response-derived value is free to land in the final state without a
// planned-vs-applied mismatch. Mirrors displayNameFollowsFriendlyNameModifier's
// established shape in resource_keyfactor_certificate_template.go.
// ---------------------------------------------------------------------------

// blankEnrollmentPatternState is defined in
// resource_keyfactor_enrollment_pattern_create_unit_test.go and reused here.

func asEnrollmentPatternConfig(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorEnrollmentPatternState) tfsdk.Config {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.Config{Schema: schema, Raw: p.Raw}
}

func asEnrollmentPatternState(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorEnrollmentPatternState) tfsdk.State {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.State{Schema: schema, Raw: p.Raw}
}

// TestUnitAssociatedRolesUsesFollowsDriverModifier is the schema-level
// regression test for F2 (associated_roles / associated_role_names).
func TestUnitAssociatedRolesUsesFollowsDriverModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	attr, ok := schema.Attributes["associated_roles"]
	if !ok {
		t.Fatal("schema has no associated_roles attribute")
	}

	found := false
	for _, m := range attr.PlanModifiers {
		if fd, ok := m.(followsDriverModifier[types.Set]); ok {
			found = true
			wantPath := path.Root("associated_role_names")
			if fd.driverPath.String() != wantPath.String() {
				t.Errorf("associated_roles: followsDriverModifier.driverPath = %q, want %q",
					fd.driverPath.String(), wantPath.String())
			}
		}
		if _, ok := m.(useStateOrNullModifier); ok {
			t.Error(
				"associated_roles: still has useStateOrNullModifier attached -- this pins the mirror to its " +
					"stale prior membership even when associated_role_names is changing this apply, which is " +
					"exactly the bug F2 fixes",
			)
		}
	}
	if !found {
		t.Error("associated_roles: expected followsDriverModifier[types.Set] among PlanModifiers")
	}
}

// TestUnitCertificateAuthoritiesUsesFollowsDriverModifier is the
// schema-level regression test for F2 (certificate_authorities /
// certificate_authority_ids) -- identical shape to the associated_roles
// check above.
func TestUnitCertificateAuthoritiesUsesFollowsDriverModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	attr, ok := schema.Attributes["certificate_authorities"]
	if !ok {
		t.Fatal("schema has no certificate_authorities attribute")
	}

	found := false
	for _, m := range attr.PlanModifiers {
		if fd, ok := m.(followsDriverModifier[types.Set]); ok {
			found = true
			wantPath := path.Root("certificate_authority_ids")
			if fd.driverPath.String() != wantPath.String() {
				t.Errorf("certificate_authorities: followsDriverModifier.driverPath = %q, want %q",
					fd.driverPath.String(), wantPath.String())
			}
		}
		if _, ok := m.(useStateOrNullModifier); ok {
			t.Error("certificate_authorities: still has useStateOrNullModifier attached -- see F2")
		}
	}
	if !found {
		t.Error("certificate_authorities: expected followsDriverModifier[types.Set] among PlanModifiers")
	}
}

// TestUnitDefaultCertificateOwnerRoleNameUsesFollowsDriverModifier is the
// schema-level regression test for F4
// (policies.default_certificate_owner_role_name /
// policies.default_certificate_owner_role_id).
func TestUnitDefaultCertificateOwnerRoleNameUsesFollowsDriverModifier(t *testing.T) {
	t.Parallel()

	attrsMap := enrollmentPatternPolicySchema()
	roleNameAttr, ok := attrsMap["default_certificate_owner_role_name"]
	if !ok {
		t.Fatal("enrollmentPatternPolicySchema has no default_certificate_owner_role_name attribute")
	}

	wantPath := path.Root("policies").AtName("default_certificate_owner_role_id")
	found := false
	for _, m := range roleNameAttr.PlanModifiers {
		if fd, ok := m.(followsDriverModifier[types.Int64]); ok {
			found = true
			if fd.driverPath.String() != wantPath.String() {
				t.Errorf("default_certificate_owner_role_name: followsDriverModifier.driverPath = %q, want %q",
					fd.driverPath.String(), wantPath.String())
			}
		}
	}
	if !found {
		t.Error("default_certificate_owner_role_name: expected followsDriverModifier[types.Int64] among PlanModifiers")
	}
}

// TestUnitFollowsDriverModifierPlansCorrectly_SetDriver simulates Terraform
// Core's plan phase for a Set-typed mirror/driver pair (the
// associated_roles/associated_role_names and certificate_authorities/
// certificate_authority_ids shape -- associated_role_names/
// certificate_authority_ids are Sets, not Lists, so that Command's
// expansion order never matters for diffing; see KeyfactorEnrollmentPattern-
// State's doc comment) by invoking followsDriverModifier[types.Set] directly
// against a real Config/State built from the actual enrollment pattern
// schema, covering every branch F2's fix depends on.
func TestUnitFollowsDriverModifierPlansCorrectly_SetDriver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	strSet := func(vals ...string) types.Set {
		s := types.Set{ElemType: types.StringType}
		for _, v := range vals {
			s.Elems = append(s.Elems, types.String{Value: v})
		}
		return s
	}
	nullStrSet := types.Set{Null: true, ElemType: types.StringType}
	unknownStrSet := types.Set{Unknown: true, ElemType: types.StringType}

	tests := []struct {
		name         string
		driverState  types.Set
		driverConfig types.Set
		wantUnknown  bool
	}{
		{
			name:         "driver undeclared (null config) -- not changing, pin mirror to prior state",
			driverState:  strSet("RoleA"),
			driverConfig: nullStrSet,
			wantUnknown:  false,
		},
		{
			name:         "driver re-declared with its current value -- not changing, pin mirror to prior state",
			driverState:  strSet("RoleA"),
			driverConfig: strSet("RoleA"),
			wantUnknown:  false,
		},
		{
			name:         "driver changing to a new value -- leave mirror unknown",
			driverState:  strSet("RoleA"),
			driverConfig: strSet("RoleB"),
			wantUnknown:  true,
		},
		{
			name:         "driver config itself unknown (chained value) -- leave mirror unknown",
			driverState:  strSet("RoleA"),
			driverConfig: unknownStrSet,
			wantUnknown:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config := blankEnrollmentPatternState()
			config.AssociatedRoleNames = tc.driverConfig
			state := blankEnrollmentPatternState()
			state.AssociatedRoleNames = tc.driverState

			cfg := asEnrollmentPatternConfig(t, ctx, schema, config)
			st := asEnrollmentPatternState(t, ctx, schema, state)

			m := followsDriverModifier[types.Set]{driverPath: path.Root("associated_role_names")}
			req := tfsdk.ModifyAttributePlanRequest{
				Config: cfg,
				State:  st,
				// associated_roles' own config/state -- not exercised by
				// the modifier's own type-specific logic (it only checks
				// IsNull/IsUnknown on these, generically), so a stand-in
				// types.List is sufficient here (associated_roles itself
				// stays a List of {id, name} objects; only the DRIVER --
				// associated_role_names -- is a Set).
				AttributeConfig: types.List{Null: true, ElemType: types.Int64Type},
				AttributeState:  types.List{ElemType: types.Int64Type},
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.List{Unknown: true, ElemType: types.Int64Type}}

			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.List)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.List: %T", resp.AttributePlan)
			}
			if got.Unknown != tc.wantUnknown {
				t.Errorf("plan.Unknown = %v, want %v (plan=%+v)", got.Unknown, tc.wantUnknown, got)
			}
		})
	}
}

// TestUnitFollowsDriverModifierPlansCorrectly_ScalarDriver is the
// Int64-driver counterpart to the List-driver test above, covering F4's
// policies.default_certificate_owner_role_name /
// policies.default_certificate_owner_role_id shape.
func TestUnitFollowsDriverModifierPlansCorrectly_ScalarDriver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	tests := []struct {
		name         string
		driverState  types.Int64
		driverConfig types.Int64
		wantUnknown  bool
	}{
		{
			name:         "driver undeclared (null config) -- not changing, pin mirror to prior state",
			driverState:  types.Int64{Value: 3},
			driverConfig: types.Int64{Null: true},
			wantUnknown:  false,
		},
		{
			name:         "driver re-declared with its current value -- not changing, pin mirror to prior state",
			driverState:  types.Int64{Value: 3},
			driverConfig: types.Int64{Value: 3},
			wantUnknown:  false,
		},
		{
			name:         "driver changing to a new id -- leave mirror unknown",
			driverState:  types.Int64{Value: 3},
			driverConfig: types.Int64{Value: 7},
			wantUnknown:  true,
		},
		{
			name:         "driver config itself unknown (chained value) -- leave mirror unknown",
			driverState:  types.Int64{Value: 3},
			driverConfig: types.Int64{Unknown: true},
			wantUnknown:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policyWith := func(id types.Int64) *EnrollmentPatternResourcePolicy {
				p := enrollmentPatternNullPolicy()
				p.DefaultCertificateOwnerRoleId = id
				return &p
			}

			config := blankEnrollmentPatternState()
			config.Policies = policyWith(tc.driverConfig)
			state := blankEnrollmentPatternState()
			state.Policies = policyWith(tc.driverState)

			cfg := asEnrollmentPatternConfig(t, ctx, schema, config)
			st := asEnrollmentPatternState(t, ctx, schema, state)

			m := followsDriverModifier[types.Int64]{driverPath: path.Root("policies").AtName("default_certificate_owner_role_id")}
			req := tfsdk.ModifyAttributePlanRequest{
				Config:          cfg,
				State:           st,
				AttributeConfig: types.String{Null: true},
				AttributeState:  types.String{Value: "RoleA"},
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.String)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
			}
			if got.Unknown != tc.wantUnknown {
				t.Errorf("plan.Unknown = %v, want %v (plan=%+v)", got.Unknown, tc.wantUnknown, got)
			}
			if !tc.wantUnknown && (got.Unknown || got.Value != "RoleA") {
				t.Errorf("plan = %+v, want the prior state value %q preserved", got, "RoleA")
			}
		})
	}
}
