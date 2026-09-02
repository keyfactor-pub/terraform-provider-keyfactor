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
// alwaysUnknownModifier fixes this by always planning the attribute as
// Unknown regardless of the declared config value -- Terraform Core accepts
// ANY final value (including Null) for an attribute planned Unknown. This
// mirrors the precedent in resource_keyfactor_certificate_template_
// inconsistent_result_unit_test.go (allowed_requesters/display_name) for the
// same "provider produced inconsistent result after apply" bug class: a
// schema-level check that the attribute is Computed with the right plan
// modifier attached, plus a modifier-level check that simulates Terraform
// Core's plan phase directly (calling Modify with a definite, non-null
// declared config value) and confirms the result is Unknown -- Unknown is
// the only planned value the framework accepts any final value for, so this
// is what actually prevents the inconsistency, not just a schema flag.
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

// TestUnitForceTemplateDefaultModifierAlwaysPlansUnknown is the root-bug
// regression test. It simulates Terraform Core's plan phase by invoking the
// modifier directly with the exact scenario that broke before the fix: a
// definite, non-null declared config value (force_template_default = true).
// Before alwaysUnknownModifier existed, no modifier ran at all for this
// attribute, so the framework's default (non-Computed) plan handling left
// resp.AttributePlan as the declared config value itself (`true`) --
// reproduced here by seeding resp.AttributePlan with the config value, the
// same starting point the framework uses for a plain Optional attribute.
func TestUnitForceTemplateDefaultModifierAlwaysPlansUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name        string
		configValue types.Bool
		stateValue  types.Bool
	}{
		{
			name:        "declared true with no prior state (Create)",
			configValue: types.Bool{Value: true},
			stateValue:  types.Bool{Null: true},
		},
		{
			name:        "declared true re-declared on Update (prior state null)",
			configValue: types.Bool{Value: true},
			stateValue:  types.Bool{Null: true},
		},
		{
			name:        "declared false",
			configValue: types.Bool{Value: false},
			stateValue:  types.Bool{Null: true},
		},
		{
			name:        "undeclared (null config)",
			configValue: types.Bool{Null: true},
			stateValue:  types.Bool{Null: true},
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
			// value ("true") that, before this fix, disagreed with the
			// always-Null final state and triggered "Provider produced
			// inconsistent result after apply".
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: tc.configValue}

			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.Bool)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.Bool: %T", resp.AttributePlan)
			}
			if !got.Unknown {
				t.Errorf(
					"force_template_default plan = %+v, want Unknown regardless of declared config value -- "+
						"a definite planned value can never match the final state (always Null), which is "+
						"exactly \"Provider produced inconsistent result after apply\"", got,
				)
			}
		})
	}
}
