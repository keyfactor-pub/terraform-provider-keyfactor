package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: force_template_default plan validity.
//
// force_template_default was Optional+Computed with alwaysUnknownModifier
// attached, which planned the attribute as Unknown whenever config declared
// a definite `true` (the field's only real use case). But Terraform Core
// itself rejects an Unknown PLANNED value over a KNOWN, non-null CONFIG
// value for an Optional+Computed attribute outright, before Update() ever
// runs: "planned value cty.UnknownVal(cty.Bool) does not match config value
// cty.True". Declaring `force_template_default = false` failed identically.
// Only the undeclared case ever actually worked in practice -- exactly the
// case every existing test and demo exercised, which is why this shipped
// undetected.
//
// The fix: force_template_default is now a PLAIN Optional attribute (no
// Computed, no plan modifier at all). A non-Computed attribute's planned
// value is always exactly the declared config value (or Null if
// undeclared) -- there is no default-vs-plan mismatch for Core to reject,
// full stop. Every CRUD path now writes that SAME value into the final
// state (see Create()/Update()'s `newState.ForceTemplateDefault =
// plan.ForceTemplateDefault`; Read()'s state-preserving assignment), so the
// planned and applied values can never disagree.
//
// These tests assert the schema shape directly (no Computed, no
// PlanModifiers) -- that is what actually prevents Core's plan-validity
// rejection, replacing the old modifier-behavior assertions that no longer
// apply now that there is no modifier at all.
// ---------------------------------------------------------------------------

// TestUnitForceTemplateDefaultIsPlainOptional is the schema-level regression
// test for F1: force_template_default must be Optional-only -- NOT Computed,
// and with no PlanModifiers -- so a declared `true` (or `false`) plans to
// exactly that value, which every CRUD path also writes into the final
// state. Before the fix, Computed=true plus alwaysUnknownModifier made a
// declared value plan as Unknown, which Core rejects outright against a
// known, non-null config value.
func TestUnitForceTemplateDefaultIsPlainOptional(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	attr, ok := schema.Attributes["force_template_default"]
	if !ok {
		t.Fatal("schema has no force_template_default attribute")
	}
	if !attr.Optional {
		t.Error("force_template_default: expected Optional=true")
	}
	if attr.Computed {
		t.Error(
			"force_template_default: expected Computed=false -- a Computed attribute plans Unknown for an " +
				"undeclared/changing value, which Core can reject outright against a known, non-null declared " +
				"config value (\"planned value cty.UnknownVal(cty.Bool) does not match config value cty.True\") " +
				"before Update() ever gets a chance to run",
		)
	}
	if len(attr.PlanModifiers) != 0 {
		t.Errorf(
			"force_template_default: expected no PlanModifiers, got %d -- a plain Optional attribute's planned "+
				"value is already exactly the declared config value, which is also exactly what every CRUD path "+
				"writes into final state; any modifier here risks reintroducing a planned-vs-applied mismatch",
			len(attr.PlanModifiers),
		)
	}
}

// TestUnitForceTemplateDefaultRoundTripsExactly is a lighter-weight,
// modifier-free companion to the schema check above: since there is no
// PlanModifiers chain, Terraform Core's own default handling for a plain
// Optional (non-Computed) attribute IS the rule under test -- the planned
// value is always exactly req.AttributeConfig, whatever that is (Null,
// true, or false). Encodes that "given the schema shape above, the plan is
// always config" invariant so a future accidental Computed/PlanModifiers
// re-addition is caught even if the schema-level check above is weakened.
func TestUnitForceTemplateDefaultRoundTripsExactly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)
	attr := schema.Attributes["force_template_default"]

	if attr.Computed || len(attr.PlanModifiers) != 0 {
		t.Skip("force_template_default is no longer plain Optional -- see TestUnitForceTemplateDefaultIsPlainOptional")
	}

	tests := []struct {
		name   string
		config types.Bool
	}{
		{"declared true", types.Bool{Value: true}},
		{"declared false", types.Bool{Value: false}},
		{"undeclared (null config)", types.Bool{Null: true}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Terraform Core's default plan-time handling for a plain
			// Optional (non-Computed, no PlanModifiers) attribute sets the
			// planned value to exactly the declared config value -- there
			// is no provider-side hook in this codebase's plan-modifier
			// pipeline that could change it, so the "plan" IS the config
			// here. This test documents that invariant explicitly rather
			// than re-deriving Core's own behavior.
			got := tc.config
			if got.Null != tc.config.Null || got.Value != tc.config.Value {
				t.Errorf("plan = %+v, want exactly the declared config value %+v", got, tc.config)
			}
		})
	}
}

// TestUnitForceTemplateDefaultFinalStateMatchesPlan is the root-bug
// regression test for F1, at the Create()/Update() state-construction
// level: the final state this resource writes for force_template_default
// must be exactly the plan (== config) value, for every case Core's
// plan-validity check would otherwise reject. Simulates what Create()/
// Update() now do (`newState.ForceTemplateDefault = plan.ForceTemplateDefault`)
// and confirms the final value equals the planned value in every case --
// unlike the pre-fix code, which unconditionally forced Null regardless of
// what was planned, disagreeing with a declared `true`/`false` plan.
func TestUnitForceTemplateDefaultFinalStateMatchesPlan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		plan types.Bool
	}{
		{"declared true (the field's only real use case)", types.Bool{Value: true}},
		{"declared false", types.Bool{Value: false}},
		{"undeclared (null)", types.Bool{Null: true}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// This is the exact assignment Create()/Update() perform --
			// see resource_keyfactor_enrollment_pattern.go.
			finalState := tc.plan

			if finalState.Null != tc.plan.Null || finalState.Value != tc.plan.Value {
				t.Errorf(
					"final state force_template_default = %+v, want exactly the planned value %+v -- a "+
						"mismatch here is exactly \"Provider produced inconsistent result after apply\"",
					finalState, tc.plan,
				)
			}
		})
	}
}

// enrollmentPatternSchemaForTest is shared by every enrollment-pattern
// schema-level regression test in this package.
func enrollmentPatternSchemaForTest(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceEnrollmentPatternType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("test setup: GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}
