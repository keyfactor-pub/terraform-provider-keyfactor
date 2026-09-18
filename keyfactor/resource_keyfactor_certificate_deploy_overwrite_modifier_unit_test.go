package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: deploymentOverwriteOnCertIDChange must be wired into
// certificate_id's PlanModifiers, not a bare tfsdk.RequiresReplace().
//
// The bug: the custom deploymentOverwriteOnCertIDChange modifier was defined
// but never attached to the schema (line ~109 of resource_keyfactor_certificate_deploy.go).
// Only tfsdk.RequiresReplace() was in certificate_id's PlanModifiers list, so
// updating certificate_id with overwrite=true still forced resource replacement
// and the Update path was unreachable.
// ---------------------------------------------------------------------------

// deploySchema returns the certificate deployment resource schema for tests.
func deploySchema(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}

// blankDeployState returns a CommandCertificateDeployment with every field
// explicitly set to a well-typed value, suitable for round-tripping through
// tfsdk.Plan.Set without type-mismatch errors.
func blankDeployState() CommandCertificateDeployment {
	return CommandCertificateDeployment{
		ID:               types.String{Value: "abc123"},
		CertificateId:    types.Int64{Value: 100},
		CertificateAlias: types.String{Null: true},
		StoreId:          types.String{Value: "store-guid-1234"},
		KeyPassword:      types.String{Null: true},
		JobParameters:    types.Map{Null: true, ElemType: types.StringType},
		Overwrite:        types.Bool{Null: true},
		Redeploy:         types.Bool{Null: true},
		SkipRemoval:      types.Bool{Null: true},
		MaxInventoryWait: types.Int64{Null: true},
	}
}

func asDeployTFState(t *testing.T, ctx context.Context, schema tfsdk.Schema, v CommandCertificateDeployment) tfsdk.State {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.State{Schema: schema, Raw: p.Raw}
}

func asDeployTFPlan(t *testing.T, ctx context.Context, schema tfsdk.Schema, v CommandCertificateDeployment) tfsdk.Plan {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return p
}

// TestUnitDeployCertIDPlanModifierIsOverwriteModifier is the schema-level
// regression test: certificate_id's PlanModifiers must contain exactly one
// deploymentOverwriteOnCertIDChange modifier — not a bare tfsdk.RequiresReplace().
// A bare tfsdk.RequiresReplace() always forces resource replacement when
// certificate_id changes, making the Update path unreachable even when
// overwrite=true is set.
func TestUnitDeployCertIDPlanModifierIsOverwriteModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := deploySchema(t, ctx)

	attr, ok := schema.Attributes["certificate_id"]
	if !ok {
		t.Fatal("schema has no certificate_id attribute")
	}
	if len(attr.PlanModifiers) != 1 {
		t.Fatalf("certificate_id: want exactly 1 plan modifier, got %d: %T",
			len(attr.PlanModifiers), attr.PlanModifiers)
	}
	_, isOverwriteModifier := attr.PlanModifiers[0].(deploymentOverwriteOnCertIDChange)
	if !isOverwriteModifier {
		t.Fatalf(
			"certificate_id plan modifier is %T, want deploymentOverwriteOnCertIDChange -- "+
				"a bare tfsdk.RequiresReplace() here always forces resource replacement when "+
				"certificate_id changes, making the Update path unreachable even with overwrite=true "+
				"(the original bug: modifier was defined but never attached to the schema)",
			attr.PlanModifiers[0],
		)
	}
}

// TestUnitDeployOverwriteModifierWithOverwriteTrueAllowsUpdate verifies that
// the modifier does NOT set RequiresReplace when overwrite=true and
// certificate_id changes, allowing Terraform to take the Update path.
func TestUnitDeployOverwriteModifierWithOverwriteTrueAllowsUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := deploySchema(t, ctx)

	stateVal := blankDeployState()
	stateVal.CertificateId = types.Int64{Value: 100}
	stateVal.Overwrite = types.Bool{Value: true}

	planVal := blankDeployState()
	planVal.CertificateId = types.Int64{Value: 999} // changed certificate
	planVal.Overwrite = types.Bool{Value: true}     // overwrite=true: allow Update

	st := asDeployTFState(t, ctx, schema, stateVal)
	pl := asDeployTFPlan(t, ctx, schema, planVal)

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("certificate_id"),
		AttributeState:  types.Int64{Value: 100},
		AttributeConfig: types.Int64{Value: 999},
		State:           st,
		Plan:            pl,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Value: 999}}

	deploymentOverwriteOnCertIDChange{}.Modify(ctx, req, resp)

	if resp.RequiresReplace {
		t.Fatal(
			"RequiresReplace=true, want false — with overwrite=true and a changed certificate_id, " +
				"the modifier must allow the Update path so the existing deployment is overwritten " +
				"in-place rather than destroyed and recreated",
		)
	}
}

// TestUnitDeployOverwriteModifierWithOverwriteFalseRequiresReplace verifies
// that the modifier DOES set RequiresReplace when overwrite=false (or not set)
// and certificate_id changes, preserving the original destroy-then-create
// behavior for operators who have not opted into overwrite.
func TestUnitDeployOverwriteModifierWithOverwriteFalseRequiresReplace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := deploySchema(t, ctx)

	cases := []struct {
		name      string
		overwrite types.Bool
	}{
		{"overwrite_null", types.Bool{Null: true}},
		{"overwrite_false", types.Bool{Value: false}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			stateVal := blankDeployState()
			stateVal.CertificateId = types.Int64{Value: 100}
			stateVal.Overwrite = c.overwrite

			planVal := blankDeployState()
			planVal.CertificateId = types.Int64{Value: 999} // changed certificate
			planVal.Overwrite = c.overwrite                 // overwrite not set / false

			st := asDeployTFState(t, ctx, schema, stateVal)
			pl := asDeployTFPlan(t, ctx, schema, planVal)

			req := tfsdk.ModifyAttributePlanRequest{
				AttributePath:   path.Root("certificate_id"),
				AttributeState:  types.Int64{Value: 100},
				AttributeConfig: types.Int64{Value: 999},
				State:           st,
				Plan:            pl,
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Value: 999}}

			deploymentOverwriteOnCertIDChange{}.Modify(ctx, req, resp)

			if !resp.RequiresReplace {
				t.Fatalf(
					"RequiresReplace=false, want true — with overwrite=%v and a changed certificate_id, "+
						"the modifier must force resource replacement so the old certificate is removed "+
						"before the new one is deployed",
					c.overwrite,
				)
			}
		})
	}
}

// TestUnitDeployOverwriteModifierNoChangeDoesNotRequireReplace verifies that
// the modifier is a no-op when certificate_id has not changed, regardless of
// the overwrite setting.
func TestUnitDeployOverwriteModifierNoChangeDoesNotRequireReplace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := deploySchema(t, ctx)

	stateVal := blankDeployState()
	stateVal.CertificateId = types.Int64{Value: 100}

	planVal := blankDeployState()
	planVal.CertificateId = types.Int64{Value: 100} // same certificate — no change

	st := asDeployTFState(t, ctx, schema, stateVal)
	pl := asDeployTFPlan(t, ctx, schema, planVal)

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("certificate_id"),
		AttributeState:  types.Int64{Value: 100},
		AttributeConfig: types.Int64{Value: 100},
		State:           st,
		Plan:            pl,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Value: 100}}

	deploymentOverwriteOnCertIDChange{}.Modify(ctx, req, resp)

	if resp.RequiresReplace {
		t.Fatal(
			"RequiresReplace=true, want false — certificate_id is unchanged so " +
				"the modifier must not trigger replacement",
		)
	}
}

// TestUnitDeployBareRequiresReplaceIgnoresOverwrite is the concrete "red"
// reproduction: run the update-with-overwrite=true scenario through a bare
// tfsdk.RequiresReplaceModifier{} (what certificate_id used before this fix)
// to prove it always requires replacement, regardless of overwrite.
func TestUnitDeployBareRequiresReplaceIgnoresOverwrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := deploySchema(t, ctx)

	stateVal := blankDeployState()
	stateVal.CertificateId = types.Int64{Value: 100}
	stateVal.Overwrite = types.Bool{Value: true}

	planVal := blankDeployState()
	planVal.CertificateId = types.Int64{Value: 999}
	planVal.Overwrite = types.Bool{Value: true}

	st := asDeployTFState(t, ctx, schema, stateVal)
	pl := asDeployTFPlan(t, ctx, schema, planVal)

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("certificate_id"),
		AttributeState:  types.Int64{Value: 100},
		AttributePlan:   types.Int64{Value: 999}, // RequiresReplaceModifier reads this field
		AttributeConfig: types.Int64{Value: 999},
		State:           st,
		Plan:            pl,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Value: 999}, RequiresReplace: false}

	// The pre-fix modifier — bare RequiresReplace always fires.
	tfsdk.RequiresReplaceModifier{}.Modify(ctx, req, resp)

	if !resp.RequiresReplace {
		t.Fatal(
			"reproduces the bug: the bare tfsdk.RequiresReplaceModifier must set RequiresReplace=true " +
				"(it has no notion of overwrite), proving it is the wrong modifier for certificate_id and " +
				"that deploymentOverwriteOnCertIDChange is required to allow the Update path",
		)
	}
}
