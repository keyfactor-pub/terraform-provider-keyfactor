package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- full-review finding F8 (Case A, verified live against
// kfclab):
//
// Command's PUT/POST body value for TemplateDefault takes precedence over
// the forceTemplateDefault query param. Declaring ONLY
// force_template_default = true, with template_default left undeclared
// (and therefore pinned by a plain tfsdk.UseStateForUnknown() to its
// prior, non-default state value), sends body TemplateDefault=false
// alongside forceTemplateDefault=true on the wire -- confirmed live: this
// is a silent no-op (neither the pattern being updated nor the template's
// existing default pattern changes).
//
// The fix: Create()/Update() force plan.TemplateDefault to true whenever
// force_template_default is genuinely true, and
// templateDefaultFollowsForceModifier keeps that from disagreeing with
// Core's plan-validity/consistency checks by planning the SAME known
// `true` directly (not Unknown, which would reintroduce the exact
// perpetual-diff bug class documented on alwaysUnknownModifier's removal).
// A ValidateConfig guard rejects the contradictory combination of
// force_template_default = true with an explicit template_default = false
// in the same config.
// ---------------------------------------------------------------------------

// TestUnitTemplateDefaultUsesFollowsForceModifier is the schema-level
// regression test: template_default must use templateDefaultFollowsForceModifier,
// not a plain tfsdk.UseStateForUnknown().
func TestUnitTemplateDefaultUsesFollowsForceModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	attr, ok := schema.Attributes["template_default"]
	if !ok {
		t.Fatal("schema has no template_default attribute")
	}

	found := false
	for _, m := range attr.PlanModifiers {
		if _, ok := m.(templateDefaultFollowsForceModifier); ok {
			found = true
		}
		if _, ok := m.(tfsdk.UseStateForUnknownModifier); ok {
			t.Error(
				"template_default: still has a plain tfsdk.UseStateForUnknown() attached -- this pins the " +
					"planned value to the prior (non-default) state even when force_template_default is " +
					"genuinely forcing it to true this apply, which is exactly the bug F8 fixes",
			)
		}
	}
	if !found {
		t.Error("template_default: expected templateDefaultFollowsForceModifier among PlanModifiers")
	}
}

// TestUnitTemplateDefaultFollowsForceModifierPlansCorrectly is the
// root-bug regression test: simulates Terraform Core's plan phase for
// template_default by invoking templateDefaultFollowsForceModifier
// directly against a real Config/State built from the actual enrollment
// pattern schema.
func TestUnitTemplateDefaultFollowsForceModifierPlansCorrectly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	tests := []struct {
		name           string
		forceConfig    types.Bool
		priorState     types.Bool
		templateConfig types.Bool // template_default's own config value
		wantValue      bool
		wantUnknown    bool
	}{
		{
			name:           "force=true, template_default undeclared, prior state false -- plans known true",
			forceConfig:    types.Bool{Value: true},
			priorState:     types.Bool{Value: false},
			templateConfig: types.Bool{Null: true},
			wantValue:      true,
			wantUnknown:    false,
		},
		{
			name:           "force=true, template_default undeclared, prior state ALREADY true -- stable, still plans true",
			forceConfig:    types.Bool{Value: true},
			priorState:     types.Bool{Value: true},
			templateConfig: types.Bool{Null: true},
			wantValue:      true,
			wantUnknown:    false,
		},
		{
			name:           "force undeclared -- behaves like UseStateForUnknown, pins to prior state",
			forceConfig:    types.Bool{Null: true},
			priorState:     types.Bool{Value: false},
			templateConfig: types.Bool{Null: true},
			wantValue:      false,
			wantUnknown:    false,
		},
		{
			name:           "force explicitly false -- behaves like UseStateForUnknown, pins to prior state",
			forceConfig:    types.Bool{Value: false},
			priorState:     types.Bool{Value: false},
			templateConfig: types.Bool{Null: true},
			wantValue:      false,
			wantUnknown:    false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config := blankEnrollmentPatternState()
			config.ForceTemplateDefault = tc.forceConfig
			config.TemplateDefault = tc.templateConfig
			state := blankEnrollmentPatternState()
			state.TemplateDefault = tc.priorState

			cfg := asEnrollmentPatternConfig(t, ctx, schema, config)
			st := asEnrollmentPatternState(t, ctx, schema, state)

			m := templateDefaultFollowsForceModifier{}
			req := tfsdk.ModifyAttributePlanRequest{
				Config:          cfg,
				State:           st,
				AttributeConfig: tc.templateConfig,
				AttributeState:  tc.priorState,
			}
			// Seed AttributePlan the way the framework's default handling
			// would for an undeclared Optional+Computed attribute (Unknown).
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Bool{Unknown: true}}

			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.Bool)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.Bool: %T", resp.AttributePlan)
			}
			if got.Unknown != tc.wantUnknown {
				t.Errorf("plan.Unknown = %v, want %v (plan=%+v)", got.Unknown, tc.wantUnknown, got)
			}
			if !tc.wantUnknown && got.Value != tc.wantValue {
				t.Errorf("plan.Value = %v, want %v", got.Value, tc.wantValue)
			}
		})
	}
}

// TestUnitTemplateDefaultFollowsForceModifierStableAcrossRepeatedPlans
// reproduces the exact live-recorded shape of F8's perpetual-diff risk:
// force_template_default = true declared and left declared across
// multiple successive plan cycles (a legitimate usage pattern -- "always
// ensure this pattern is the default") must settle to a STABLE plan, not
// show "template_default = ... -> (known after apply)" forever.
func TestUnitTemplateDefaultFollowsForceModifierStableAcrossRepeatedPlans(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)
	m := templateDefaultFollowsForceModifier{}

	runCycle := func(t *testing.T, label string, priorState types.Bool) types.Bool {
		t.Helper()
		config := blankEnrollmentPatternState()
		config.ForceTemplateDefault = types.Bool{Value: true}
		config.TemplateDefault = types.Bool{Null: true}
		state := blankEnrollmentPatternState()
		state.TemplateDefault = priorState

		cfg := asEnrollmentPatternConfig(t, ctx, schema, config)
		st := asEnrollmentPatternState(t, ctx, schema, state)

		req := tfsdk.ModifyAttributePlanRequest{
			Config:          cfg,
			State:           st,
			AttributeConfig: types.Bool{Null: true},
			AttributeState:  priorState,
		}
		resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Bool{Unknown: true}}
		m.Modify(ctx, req, resp)

		got, ok := resp.AttributePlan.(types.Bool)
		if !ok {
			t.Fatalf("%s: resp.AttributePlan is not types.Bool: %T", label, resp.AttributePlan)
		}
		if got.Unknown {
			t.Fatalf(
				"%s: template_default plan = %+v, want a stable known value -- an Unknown plan here on a "+
					"clean, repeated force_template_default=true apply is exactly the perpetual "+
					"\"(known after apply)\" diff this fix must avoid",
				label, got,
			)
		}
		if !got.Value {
			t.Fatalf("%s: template_default plan = %+v, want true", label, got)
		}
		return got
	}

	// First cycle: prior state is false (not yet the default).
	first := runCycle(t, "first apply (becomes default)", types.Bool{Value: false})
	// Second cycle: prior state now reflects the FIRST cycle's own result
	// (true) -- simulating the settled, converged state after the first
	// apply actually took effect.
	runCycle(t, "second apply (already default, re-declared)", first)
}

// TestUnitValidateEnrollmentPatternConfigConstraints_ForceTemplateDefaultContradiction
// is the regression test for F8's ValidateConfig guard: force_template_default
// = true combined with an explicit template_default = false in the same
// config must be rejected as contradictory, rather than silently resolved
// in the directive's favor.
func TestUnitValidateEnrollmentPatternConfigConstraints_ForceTemplateDefaultContradiction(t *testing.T) {
	t.Parallel()

	t.Run("force=true with explicit template_default=false is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			ForceTemplateDefault: types.Bool{Value: true},
			TemplateDefault:      types.Bool{Value: false},
			UseADPermissions:     types.Bool{Null: true},
			AssociatedRoleNames:  types.Set{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if !hasAttributeError(diags, "Contradictory force_template_default and template_default") {
			t.Errorf("diags = %+v, want the contradiction error", diags)
		}
	})

	t.Run("force=true with template_default undeclared is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			ForceTemplateDefault: types.Bool{Value: true},
			TemplateDefault:      types.Bool{Null: true},
			UseADPermissions:     types.Bool{Null: true},
			AssociatedRoleNames:  types.Set{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Contradictory force_template_default and template_default") {
			t.Errorf("diags = %+v, want no contradiction error when template_default is undeclared", diags)
		}
	})

	t.Run("force=true with explicit template_default=true is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			ForceTemplateDefault: types.Bool{Value: true},
			TemplateDefault:      types.Bool{Value: true},
			UseADPermissions:     types.Bool{Null: true},
			AssociatedRoleNames:  types.Set{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Contradictory force_template_default and template_default") {
			t.Errorf("diags = %+v, want no contradiction error when template_default agrees with force", diags)
		}
	})

	t.Run("force undeclared with template_default=false is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			ForceTemplateDefault: types.Bool{Null: true},
			TemplateDefault:      types.Bool{Value: false},
			UseADPermissions:     types.Bool{Null: true},
			AssociatedRoleNames:  types.Set{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Contradictory force_template_default and template_default") {
			t.Errorf("diags = %+v, want no contradiction error when force is undeclared", diags)
		}
	})

	t.Run("force unknown is never a contradiction error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			ForceTemplateDefault: types.Bool{Unknown: true},
			TemplateDefault:      types.Bool{Value: false},
			UseADPermissions:     types.Bool{Null: true},
			AssociatedRoleNames:  types.Set{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Contradictory force_template_default and template_default") {
			t.Errorf("diags = %+v, want no contradiction error when force is Unknown", diags)
		}
	})
}
