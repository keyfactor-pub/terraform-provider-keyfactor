package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnitDeploymentModifyPlan_UnknownIncludePrivateKeyIsAnError(t *testing.T) {
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())

	mk := func(ipk types.Bool) CommandCertificateDeployment {
		return CommandCertificateDeployment{
			ID:                types.String{Value: "id"},
			CertificateId:     types.Int64{Value: 1},
			CertificateAlias:  types.String{Null: true},
			StoreId:           types.String{Value: "store"},
			KeyPassword:       types.String{Null: true},
			JobParameters:     types.Map{Null: true, ElemType: types.StringType},
			Overwrite:         types.Bool{Null: true},
			Redeploy:          types.Bool{Null: true},
			SkipRemoval:       types.Bool{Null: true},
			IncludePrivateKey: ipk,
		}
	}
	run := func(state, plan types.Bool) *tfsdk.ModifyResourcePlanResponse {
		st := stateWith(t, schema, mk(state))
		pl := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, mk(plan)).Raw}
		resp := &tfsdk.ModifyResourcePlanResponse{Plan: pl}
		resourceCommandCertificateDeployment{}.ModifyPlan(ctx, tfsdk.ModifyResourcePlanRequest{State: st, Plan: pl}, resp)
		return resp
	}

	resp := run(types.Bool{Value: true}, types.Bool{Unknown: true})
	require.True(t, resp.Diagnostics.HasError(), "an unknown include_private_key must be rejected at plan time")
	assert.Contains(t, resp.Diagnostics[0].Detail(), "must be known at plan time")

	// Known values are unaffected.
	assert.False(t, run(types.Bool{Value: true}, types.Bool{Value: true}).Diagnostics.HasError())
	assert.False(t, run(types.Bool{Null: true}, types.Bool{Value: true}).Diagnostics.HasError())
}

// ---- #3: the include_private_key replace decision lives in ModifyPlan only. ----

func deploymentForModifyPlan(ipk, skip types.Bool) CommandCertificateDeployment {
	return CommandCertificateDeployment{
		ID:                types.String{Value: "id"},
		CertificateId:     types.Int64{Value: 1},
		CertificateAlias:  types.String{Null: true},
		StoreId:           types.String{Value: "store"},
		KeyPassword:       types.String{Null: true},
		JobParameters:     types.Map{Null: true, ElemType: types.StringType},
		Overwrite:         types.Bool{Null: true},
		Redeploy:          types.Bool{Null: true},
		SkipRemoval:       skip,
		IncludePrivateKey: ipk,
	}
}

func runDeploymentModifyPlan(t *testing.T, state, plan CommandCertificateDeployment) *tfsdk.ModifyResourcePlanResponse {
	t.Helper()
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	st := stateWith(t, schema, state)
	pl := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, plan).Raw}
	resp := &tfsdk.ModifyResourcePlanResponse{Plan: pl}
	resourceCommandCertificateDeployment{}.ModifyPlan(ctx, tfsdk.ModifyResourcePlanRequest{State: st, Plan: pl}, resp)
	return resp
}

func requiresReplaceIncludePrivateKey(resp *tfsdk.ModifyResourcePlanResponse) bool {
	for _, p := range resp.RequiresReplace {
		if p.Equal(path.Root("include_private_key")) {
			return true
		}
	}
	return false
}

func TestUnitDeploymentModifyPlan_IncludePrivateKeyReplaceDecision(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	cases := []struct {
		name        string
		state, plan types.Bool
		wantReplace bool
	}{
		{"null->null", null, null, false},
		{"null->true", null, tr, false},
		{"true->null", tr, null, false},
		{"true->true", tr, tr, false},
		{"false->false", fa, fa, false},
		{"null->false", null, fa, true},
		{"true->false", tr, fa, true},
		{"false->true", fa, tr, true},
		{"false->null", fa, null, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := runDeploymentModifyPlan(t, deploymentForModifyPlan(c.state, null), deploymentForModifyPlan(c.plan, null))
			require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			assert.Equal(t, c.wantReplace, requiresReplaceIncludePrivateKey(resp))
		})
	}
}

// An include_private_key change still replaces the deployment, but is rejected while the PRIOR
// state has skip_removal = true; skip_removal flipping to true in the same apply is fine.
func TestUnitDeploymentModifyPlan_IncludePrivateKeyReplaceAndSkipRemoval(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}

	resp := runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, tr), deploymentForModifyPlan(fa, tr))
	assert.True(t, resp.Diagnostics.HasError(), "state skip_removal = true blocks the replace")
	assert.True(t, requiresReplaceIncludePrivateKey(resp))

	resp = runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, fa), deploymentForModifyPlan(fa, tr))
	assert.False(t, resp.Diagnostics.HasError(), "skip_removal = true only in the plan does not block: %v", resp.Diagnostics)
	assert.True(t, requiresReplaceIncludePrivateKey(resp))

	resp = runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, tr), deploymentForModifyPlan(tr, tr))
	assert.False(t, resp.Diagnostics.HasError(), "no include_private_key change is never blocked")
	assert.False(t, requiresReplaceIncludePrivateKey(resp))

	resp = runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, null), deploymentForModifyPlan(types.Bool{Unknown: true}, null))
	assert.True(t, resp.Diagnostics.HasError(), "unknown include_private_key is still rejected")
}

// The schema attribute carries no replace modifier of its own any more: ModifyPlan is the only place
// the decision is made.
func TestUnitDeploymentSchema_IncludePrivateKeyHasNoAttributePlanModifier(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	assert.Empty(t, schema.Attributes["include_private_key"].PlanModifiers)
}

// ---- #1: create_before_destroy is documented at resource level. ----

func TestUnitDeploymentResourceDescriptionMentionsCreateBeforeDestroy(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	assert.Contains(t, schema.Description, "create_before_destroy")
	assert.Contains(t, schema.MarkdownDescription, "create_before_destroy")
	assert.Contains(t, schema.Description, "same certificate and alias")
}

func TestUnitIncludePrivateKeyOrDefault(t *testing.T) {
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Null: true}))
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Unknown: true}))
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Value: true}))
	assert.False(t, includePrivateKeyOrDefault(types.Bool{Value: false}))
}

func TestUnitIncludePrivateKeyChangeRequiresReplace(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	cases := []struct {
		name        string
		state, plan types.Bool
		want        bool
	}{
		{"null->null", null, null, false},
		{"null->true", null, tr, false},
		{"true->null", tr, null, false},
		{"true->true", tr, tr, false},
		{"false->false", fa, fa, false},
		{"null->false", null, fa, true},
		{"true->false", tr, fa, true},
		{"false->true", fa, tr, true},
		{"false->null", fa, null, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, includePrivateKeyChangeRequiresReplace(c.state, c.plan))
		})
	}
}

// Delete reads skip_removal from PRIOR STATE, so only state skip_removal = true blocks an
// include_private_key replace. Plan-only true (set in the same apply), unknown and null plan
// values must not block.
func TestUnitIncludePrivateKeyReplaceBlockedBySkipRemoval(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	unk := types.Bool{Unknown: true}
	assert.True(t, includePrivateKeyReplaceBlockedBySkipRemoval(tr), "state true blocks")
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(fa), "state false does not block")
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(null), "state null does not block")
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(unk), "state unknown does not block")
}

func TestUnitExistingEntryPrivateKeyDiagnostic_MentionsCreateBeforeDestroy(t *testing.T) {
	summary, detail := existingEntryPrivateKeyDiagnostic(42, "store-1", "alias-1")
	assert.Contains(t, summary, "private key")
	assert.Contains(t, detail, "create_before_destroy")
	assert.Contains(t, detail, "'42'")
	assert.Contains(t, detail, "store-1 (alias-1)")
	assert.Contains(t, detail, "include_private_key = true")
}

func TestUnitIncludePrivateKeyDescriptionMentionsCreateBeforeDestroy(t *testing.T) {
	schema, diags := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	assert.False(t, diags.HasError())
	attr, ok := schema.Attributes["include_private_key"]
	if assert.True(t, ok) {
		assert.Contains(t, attr.Description, "create_before_destroy")
		assert.Contains(t, attr.Description, "current state")
	}
}

// runDeploymentModifyPlanWithConfig is runDeploymentModifyPlan with the Config the framework always
// supplies (here the planned values).
func runDeploymentModifyPlanWithConfig(t *testing.T, state, plan CommandCertificateDeployment) *tfsdk.ModifyResourcePlanResponse {
	t.Helper()
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	st := stateWith(t, schema, state)
	planRaw := stateWith(t, schema, plan).Raw
	pl := tfsdk.Plan{Schema: schema, Raw: planRaw}
	resp := &tfsdk.ModifyResourcePlanResponse{Plan: pl}
	resourceCommandCertificateDeployment{}.ModifyPlan(ctx, tfsdk.ModifyResourcePlanRequest{
		Config: tfsdk.Config{Schema: schema, Raw: planRaw},
		State:  st,
		Plan:   pl,
	}, resp)
	return resp
}

// F2: with skip_removal = true in the prior state and include_private_key = false planned, a
// replacement for ANY reason is rejected at plan time: Delete would leave the entry in the store and
// Create would then refuse it.
func TestUnitDeploymentModifyPlan_NonPrivateKeyReplaceWithSkipRemovalIsRejected(t *testing.T) {
	base := func() CommandCertificateDeployment {
		d := deploymentForModifyPlan(types.Bool{Value: false}, types.Bool{Value: true})
		d.StoreId = types.String{Value: "store"}
		return d
	}
	for _, tc := range []struct {
		name     string
		mutate   func(*CommandCertificateDeployment)
		wantFail bool
	}{
		{"certificate_id change", func(d *CommandCertificateDeployment) { d.CertificateId = types.Int64{Value: 2} }, true},
		{"certificate_store_id change", func(d *CommandCertificateDeployment) { d.StoreId = types.String{Value: "other"} }, true},
		{"certificate_alias change", func(d *CommandCertificateDeployment) { d.CertificateAlias = types.String{Value: "a"} }, true},
		{"key_password change", func(d *CommandCertificateDeployment) { d.KeyPassword = types.String{Value: "pw"} }, true},
		{"redeploy = true", func(d *CommandCertificateDeployment) { d.Redeploy = types.Bool{Value: true} }, true},
		{"no change", func(d *CommandCertificateDeployment) {}, false},
		{"non-replacing change (job_parameters)", func(d *CommandCertificateDeployment) {
			d.JobParameters = types.Map{ElemType: types.StringType, Elems: map[string]attr.Value{"k": types.String{Value: "v"}}}
		}, false},
		{"redeploy = false", func(d *CommandCertificateDeployment) { d.Redeploy = types.Bool{Value: false} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := base()
			tc.mutate(&plan)
			resp := runDeploymentModifyPlanWithConfig(t, base(), plan)
			if !tc.wantFail {
				assert.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics)
				return
			}
			require.True(t, resp.Diagnostics.HasError(), "a replacement with skip_removal = true in state and include_private_key = false must be rejected")
			assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "skip_removal = false first")
		})
	}
}

// The new rejection only applies while the planned include_private_key is false and skip_removal
// is true in the PRIOR STATE.
func TestUnitDeploymentModifyPlan_NonPrivateKeyReplaceOutsideTheUnsafeCombinationIsAllowed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ipk, skip types.Bool
	}{
		{"include_private_key unset (default true)", types.Bool{Null: true}, types.Bool{Value: true}},
		{"include_private_key true", types.Bool{Value: true}, types.Bool{Value: true}},
		{"skip_removal false", types.Bool{Value: false}, types.Bool{Value: false}},
		{"skip_removal unset", types.Bool{Value: false}, types.Bool{Null: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := deploymentForModifyPlan(tc.ipk, tc.skip)
			plan := deploymentForModifyPlan(tc.ipk, tc.skip)
			plan.CertificateId = types.Int64{Value: 2}
			resp := runDeploymentModifyPlanWithConfig(t, state, plan)
			assert.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics)
		})
	}
}

// F9: a failure to read the prior state or the plan must be reported, not silently swallowed.
func TestUnitDeploymentModifyPlan_UnreadablePlanOrStateIsReported(t *testing.T) {
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	good := stateWith(t, schema, deploymentForModifyPlan(types.Bool{Value: false}, types.Bool{Value: true}))
	bad := tftypes.NewValue(tftypes.String, "not an object")

	t.Run("plan", func(t *testing.T) {
		pl := tfsdk.Plan{Schema: schema, Raw: bad}
		resp := &tfsdk.ModifyResourcePlanResponse{Plan: pl}
		resourceCommandCertificateDeployment{}.ModifyPlan(ctx, tfsdk.ModifyResourcePlanRequest{State: good, Plan: pl}, resp)
		assert.True(t, resp.Diagnostics.HasError(), "an unreadable plan must produce an error diagnostic")
	})
	t.Run("state", func(t *testing.T) {
		st := tfsdk.State{Schema: schema, Raw: bad}
		pl := tfsdk.Plan{Schema: schema, Raw: good.Raw}
		resp := &tfsdk.ModifyResourcePlanResponse{Plan: pl}
		resourceCommandCertificateDeployment{}.ModifyPlan(ctx, tfsdk.ModifyResourcePlanRequest{State: st, Plan: pl}, resp)
		assert.True(t, resp.Diagnostics.HasError(), "an unreadable prior state must produce an error diagnostic")
	})
}

// F2: the resource description tells users that `terraform apply -replace` with skip_removal = true
// and include_private_key = false is not supported (the provider cannot see it in the plan).
func TestUnitDeploymentResourceDescriptionMentionsApplyReplaceLimitation(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	for name, desc := range map[string]string{"Description": schema.Description, "MarkdownDescription": schema.MarkdownDescription} {
		assert.Contains(t, desc, "-replace", name)
		assert.Contains(t, desc, "skip_removal", name)
		assert.Contains(t, desc, "include_private_key", name)
	}
}

// ---- #5: an unknown include_private_key is only rejected when nothing else replaces the deployment. ----

func TestUnitDeploymentModifyPlan_UnknownIncludePrivateKeyWithOtherReplaceIsAllowed(t *testing.T) {
	tr := types.Bool{Value: true}
	unk := types.Bool{Unknown: true}
	null := types.Bool{Null: true}

	// certificate_id changes (RequiresReplace attribute): the deployment is replaced anyway and the
	// value resolves before Create.
	plan := deploymentForModifyPlan(unk, null)
	plan.CertificateId = types.Int64{Value: 2}
	resp := runDeploymentModifyPlanWithConfig(t, deploymentForModifyPlan(tr, null), plan)
	assert.False(t, resp.Diagnostics.HasError(), "unknown include_private_key during another replacement must pass: %v", resp.Diagnostics)

	// Nothing else replaces the deployment: still rejected.
	resp = runDeploymentModifyPlanWithConfig(t, deploymentForModifyPlan(tr, null), deploymentForModifyPlan(unk, null))
	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Detail(), "must be known at plan time")

	// A non-replacing change (job_parameters) is not a replacement either.
	plan = deploymentForModifyPlan(unk, null)
	plan.JobParameters = types.Map{ElemType: types.StringType, Elems: map[string]attr.Value{"k": types.String{Value: "v"}}}
	resp = runDeploymentModifyPlanWithConfig(t, deploymentForModifyPlan(tr, null), plan)
	assert.True(t, resp.Diagnostics.HasError())
}

// ---- Nit: registry markdown renders code in backticks, not double quotes. ----

func TestUnitDeploymentMarkdownDescriptionUsesBackticksForSnippets(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	md := schema.MarkdownDescription
	for _, snippet := range []string{"/OrchestratorJobs/Custom", "keyfactor_certificate_deployment", "keyfactor_certificate_store", "skip_removal = true", "include_private_key = false", "terraform apply -replace"} {
		assert.Contains(t, md, "`"+snippet+"`", snippet)
		assert.NotContains(t, md, `"`+snippet+`"`, snippet)
	}
	assert.Contains(t, md, "`lifecycle { create_before_destroy = true }`")
	assert.NotContains(t, md, `"lifecycle`)
}

// Class B: deploymentOverwriteOnCertIDChange reports a failure to read certificate_id from the
// state/plan instead of comparing two zero values.
func TestUnitDeploymentOverwriteOnCertIDChange_UnreadableAttributeIsReported(t *testing.T) {
	ctx := context.Background()
	emptyObj := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}, map[string]tftypes.Value{})
	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath: path.Root("certificate_id"),
		State:         tfsdk.State{Schema: tfsdk.Schema{}, Raw: emptyObj},
		Plan:          tfsdk.Plan{Schema: tfsdk.Schema{}, Raw: emptyObj},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{}
	deploymentOverwriteOnCertIDChange{}.Modify(ctx, req, resp)
	assert.True(t, resp.Diagnostics.HasError(), "an unreadable certificate_id must be reported")
	assert.False(t, resp.RequiresReplace)
}
