package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- PR #210 full-review finding FIX-1:
//
// force_template_default was Optional-only (no Computed, no plan modifier).
// A non-Computed attribute's planned value is always exactly the declared
// config value, so declaring force_template_default = true (the field's
// only real use case -- it's a one-shot directive to force this pattern to
// become the template's default) planned the attribute as `true`. But every
// CRUD path in this file (Create/Read/Update/ImportState) unconditionally
// sets the FINAL state's force_template_default to Null, because Command
// never persists it -- it's a write-only, one-shot directive, not a stored
// setting. Terraform Core rejects an apply whose final value disagrees with
// a definite (non-Unknown) planned value, so applying
// `force_template_default = true` failed with "Provider produced
// inconsistent result after apply" on literally the only scenario this
// attribute exists for.
//
// alwaysUnknownModifier fixes this by planning the attribute as Unknown when
// config declares a definite `true` (or is itself still Unknown) --
// Terraform Core accepts ANY final value (including Null) for an attribute
// planned Unknown. This mirrors the precedent in resource_keyfactor_
// certificate_template_inconsistent_result_unit_test.go (allowed_requesters/
// display_name) for the same "provider produced inconsistent result after
// apply" bug class: a schema-level check that the attribute is Computed
// with the right plan modifier attached, plus a modifier-level check that
// simulates Terraform Core's plan phase directly (calling Modify with a
// definite, non-null declared config value) and confirms the result is
// Unknown -- Unknown is the only planned value the framework accepts any
// final value for, so this is what actually prevents the inconsistency, not
// just a schema flag.
//
// Round 2 finding FIX-A: the original modifier planned Unknown
// UNCONDITIONALLY, regardless of config/state, which broke the OTHER common
// case -- force_template_default left undeclared (or explicitly false) --
// by making it show `null -> (known after apply)` on every single
// subsequent `terraform plan`, forever, even with zero declared changes.
// The tests below now assert Null (not Unknown) for that case, and add a
// dedicated stability check across repeated plan cycles.
// ---------------------------------------------------------------------------

func enrollmentPatternSchemaForTest(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceEnrollmentPatternType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("test setup: GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}

// TestUnitForceTemplateDefaultIsComputedWithAlwaysUnknownModifier is the
// schema-level regression test: force_template_default must be Computed (in
// addition to Optional) with alwaysUnknownModifier attached, so a declared
// `true` legally plans to Unknown instead of a definite `true` that the
// (always-Null) final state could never match.
func TestUnitForceTemplateDefaultIsComputedWithAlwaysUnknownModifier(t *testing.T) {
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
	if !attr.Computed {
		t.Fatal(
			"force_template_default: expected Computed=true, got false -- without Computed, a declared " +
				"`true` plans to exactly `true`, and every CRUD path setting the final state to Null " +
				"produces \"Provider produced inconsistent result after apply\"",
		)
	}

	found := false
	for _, m := range attr.PlanModifiers {
		if _, ok := m.(alwaysUnknownModifier); ok {
			found = true
		}
	}
	if !found {
		t.Error("force_template_default: expected alwaysUnknownModifier among PlanModifiers")
	}
}

// TestUnitForceTemplateDefaultModifierPlansCorrectly is the root-bug
// regression test, covering both round 1 (FIX-1) and round 2 (FIX-A). It
// simulates Terraform Core's plan phase by invoking the modifier directly:
//   - config declares a definite `true` (the field's only real use case) or
//     is itself Unknown (chained from a not-yet-applied resource) -> plan
//     must be Unknown, so Core accepts the always-Null final state (FIX-1).
//   - config is undeclared (Null) or explicitly `false` -> plan must be a
//     stable Null, NOT Unknown, so a clean drift-check plan doesn't show a
//     perpetual `null -> (known after apply)` diff (FIX-A).
//
// Before FIX-1, no modifier ran at all for this attribute, so the
// framework's default (non-Computed) plan handling left resp.AttributePlan
// as the declared config value itself (`true`) -- reproduced here by
// seeding resp.AttributePlan with the config value, the same starting point
// the framework uses for a plain Optional attribute.
func TestUnitForceTemplateDefaultModifierPlansCorrectly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name        string
		configValue types.Bool
		stateValue  types.Bool
		wantUnknown bool
	}{
		{
			name:        "declared true with no prior state (Create)",
			configValue: types.Bool{Value: true},
			stateValue:  types.Bool{Null: true},
			wantUnknown: true,
		},
		{
			name:        "declared true re-declared on Update (prior state null)",
			configValue: types.Bool{Value: true},
			stateValue:  types.Bool{Null: true},
			wantUnknown: true,
		},
		{
			name:        "config itself unknown (chained from a not-yet-applied resource)",
			configValue: types.Bool{Unknown: true},
			stateValue:  types.Bool{Null: true},
			wantUnknown: true,
		},
		{
			name:        "declared false",
			configValue: types.Bool{Value: false},
			stateValue:  types.Bool{Null: true},
			wantUnknown: false,
		},
		{
			name:        "undeclared (null config), no prior state",
			configValue: types.Bool{Null: true},
			stateValue:  types.Bool{Null: true},
			wantUnknown: false,
		},
		{
			name:        "undeclared (null config), refresh-only plan after apply",
			configValue: types.Bool{Null: true},
			stateValue:  types.Bool{Null: true},
			wantUnknown: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := alwaysUnknownModifier{}
			req := tfsdk.ModifyAttributePlanRequest{
				AttributeConfig: tc.configValue,
				AttributeState:  tc.stateValue,
			}
			// Seed AttributePlan with the config value -- what the framework's
			// default (pre-modifier) handling would produce for a plain
			// Optional, non-Computed attribute. This is the exact planned
			// value ("true") that, before FIX-1, disagreed with the
			// always-Null final state and triggered "Provider produced
			// inconsistent result after apply".
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: tc.configValue}

			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.Bool)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.Bool: %T", resp.AttributePlan)
			}
			if tc.wantUnknown {
				if !got.Unknown {
					t.Errorf(
						"force_template_default plan = %+v, want Unknown -- a definite planned value can "+
							"never match the final state (always Null), which is exactly \"Provider produced "+
							"inconsistent result after apply\"", got,
					)
				}
				return
			}
			if got.Unknown {
				t.Errorf(
					"force_template_default plan = %+v, want a stable Null (not Unknown) -- an Unknown plan "+
						"here is exactly the perpetual 'null -> (known after apply)' diff FIX-A fixes", got,
				)
			}
			if !got.Null {
				t.Errorf("force_template_default plan = %+v, want Null", got)
			}
		})
	}
}

// TestUnitForceTemplateDefaultModifierStableAcrossRepeatedPlans reproduces
// the round 2 perpetual-diff bug end to end (FIX-A): before this fix,
// alwaysUnknownModifier planned Unknown unconditionally, so a config that
// never declares force_template_default (the overwhelmingly common case)
// still showed `force_template_default = null -> (known after apply)` on
// every single `terraform plan`, forever -- even with zero declared
// changes, defeating a clean plan -> apply -> import -> drift-check ->
// destroy lifecycle (see this repo's CLAUDE.md). This simulates two
// successive plan cycles against an undeclared config and confirms the plan
// is a stable Null both times, not Unknown on either.
func TestUnitForceTemplateDefaultModifierStableAcrossRepeatedPlans(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := alwaysUnknownModifier{}

	runCycle := func(t *testing.T, label string) {
		t.Helper()
		req := tfsdk.ModifyAttributePlanRequest{
			AttributeConfig: types.Bool{Null: true},
			AttributeState:  types.Bool{Null: true},
		}
		resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Bool{Null: true}}
		m.Modify(ctx, req, resp)
		got, ok := resp.AttributePlan.(types.Bool)
		if !ok {
			t.Fatalf("%s: resp.AttributePlan is not types.Bool: %T", label, resp.AttributePlan)
		}
		if got.Unknown || !got.Null {
			t.Fatalf(
				"%s: force_template_default plan = %+v, want a stable Null -- an Unknown plan here on a "+
					"clean, undeclared-config drift-check is exactly the perpetual diff FIX-A fixes",
				label, got,
			)
		}
	}

	runCycle(t, "first plan cycle (initial create)")
	runCycle(t, "second plan cycle (drift-check after apply)")
}
