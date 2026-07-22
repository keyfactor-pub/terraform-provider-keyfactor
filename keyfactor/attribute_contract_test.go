package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitDeclaredInConfig covers declaredInConfig's contract directly: nil
// and Null are undeclared; Unknown and any concrete value are declared.
func TestUnitDeclaredInConfig(t *testing.T) {
	cases := []struct {
		name string
		v    types.Int64
		want bool
	}{
		{"nil-typed zero value is null -> undeclared", types.Int64{Null: true}, false},
		{"unknown -> declared", types.Int64{Unknown: true}, true},
		{"known value -> declared", types.Int64{Value: 60}, true},
		{"known zero value -> declared", types.Int64{Value: 0}, true},
	}
	for _, tc := range cases {
		t.Run(
			tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, declaredInConfig(tc.v))
			},
		)
	}
}

// pairedTestModel is a minimal two-attribute schema used only to exercise
// pairedVariantModifier in isolation, standing in for a real mutually
// exclusive attribute pair (e.g. an interval-based vs. daily-time-based
// schedule variant) without depending on any specific resource's schema.
type pairedTestModel struct {
	Interval types.Int64  `tfsdk:"interval"`
	Daily    types.String `tfsdk:"daily"`
}

func pairedTestSchema() tfsdk.Schema {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"interval": {Type: types.Int64Type, Optional: true, Computed: true},
			"daily":    {Type: types.StringType, Optional: true, Computed: true},
		},
	}
}

// buildPairedTestConfig builds a tfsdk.Config wrapping pairedTestSchema from
// a pairedTestModel. tfsdk.Config has no Set method of its own; build the Raw
// value the same way Plan/State do (via a throwaway Plan) and reuse it, since
// Config/Plan/State all wrap an identically-shaped (Raw tftypes.Value, Schema
// tfsdk.Schema) pair. Mirrors the same workaround already used in
// resource_keyfactor_security_identity_unit_test.go.
func buildPairedTestConfig(t *testing.T, ctx context.Context, schema tfsdk.Schema, model pairedTestModel) tfsdk.Config {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &model); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	return tfsdk.Config{Schema: schema, Raw: p.Raw}
}

// TestUnitPairedVariantModifier_DeclaredValueUntouched covers step 1: when
// this attribute's own plan is already known (the config declared it,
// including an explicit clear sentinel like 0), the modifier must not touch
// it -- regardless of what the sibling looks like.
func TestUnitPairedVariantModifier_DeclaredValueUntouched(t *testing.T) {
	ctx := context.Background()
	schema := pairedTestSchema()

	config := buildPairedTestConfig(
		t, ctx, schema, pairedTestModel{
			Interval: types.Int64{Value: 60},
			Daily:    types.String{Null: true},
		},
	)
	state := tfsdk.State{Schema: schema}
	if d := state.Set(
		ctx, &pairedTestModel{
			Interval: types.Int64{Value: 30},
			Daily:    types.String{Null: true},
		},
	); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("interval"),
		Config:          config,
		State:           state,
		AttributeConfig: types.Int64{Value: 60},
		AttributeState:  types.Int64{Value: 30},
		AttributePlan:   types.Int64{Value: 60}, // already known: config declared 60 directly.
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	pairedWith("daily").Modify(ctx, req, resp)

	assert.Equal(t, types.Int64{Value: 60}, resp.AttributePlan, "a known (declared) plan value must be left untouched")
	assert.False(t, resp.Diagnostics.HasError())
}

// TestUnitPairedVariantModifier_SiblingDeclaredPlansNull covers step 2: this
// attribute's own plan is Unknown (undeclared, so Terraform Core hasn't
// resolved it), but the sibling variant IS declared in config -- this
// attribute must plan to Null (not resurrect the prior state value) so the
// diff on a variant switch (e.g. interval 60 -> null) is truthful. This is
// the fix for the F182-1-class "resurrection" bug: a bare UseStateForUnknown
// would instead copy the stale interval back onto the plan.
func TestUnitPairedVariantModifier_SiblingDeclaredPlansNull(t *testing.T) {
	ctx := context.Background()
	schema := pairedTestSchema()

	config := buildPairedTestConfig(
		t, ctx, schema, pairedTestModel{
			Interval: types.Int64{Null: true},         // undeclared
			Daily:    types.String{Value: "07:00:00"}, // sibling declared
		},
	)
	state := tfsdk.State{Schema: schema}
	if d := state.Set(
		ctx, &pairedTestModel{
			Interval: types.Int64{Value: 60}, // prior interval schedule, now being superseded
			Daily:    types.String{Null: true},
		},
	); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("interval"),
		Config:          config,
		State:           state,
		AttributeConfig: types.Int64{Null: true},
		AttributeState:  types.Int64{Value: 60},
		AttributePlan:   types.Int64{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	pairedWith("daily").Modify(ctx, req, resp)

	assert.False(t, resp.Diagnostics.HasError(), "unexpected diagnostics: %+v", resp.Diagnostics)
	got, ok := resp.AttributePlan.(types.Int64)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.Int64, got %T", resp.AttributePlan) {
		assert.True(t, got.Null, "expected the plan to be explicitly Null when the sibling variant is declared, got %+v", got)
		assert.False(t, got.Unknown)
	}
}

// TestUnitPairedVariantModifier_NeitherDeclaredCopiesState covers step 3: when
// neither this attribute nor its sibling is declared, the modifier falls back
// to useStateOrNullModifier semantics and copies the prior state's value
// forward, so an unrelated Update doesn't show spurious "(known after apply)"
// noise or -- worse -- let buildCARequest-style callers omit/clear the field.
func TestUnitPairedVariantModifier_NeitherDeclaredCopiesState(t *testing.T) {
	ctx := context.Background()
	schema := pairedTestSchema()

	config := buildPairedTestConfig(
		t, ctx, schema, pairedTestModel{
			Interval: types.Int64{Null: true},
			Daily:    types.String{Null: true},
		},
	)
	state := tfsdk.State{Schema: schema}
	if d := state.Set(
		ctx, &pairedTestModel{
			Interval: types.Int64{Value: 60},
			Daily:    types.String{Null: true},
		},
	); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("interval"),
		Config:          config,
		State:           state,
		AttributeConfig: types.Int64{Null: true},
		AttributeState:  types.Int64{Value: 60},
		AttributePlan:   types.Int64{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	pairedWith("daily").Modify(ctx, req, resp)

	assert.False(t, resp.Diagnostics.HasError(), "unexpected diagnostics: %+v", resp.Diagnostics)
	got, ok := resp.AttributePlan.(types.Int64)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.Int64, got %T", resp.AttributePlan) {
		assert.Equal(t, int64(60), got.Value, "the prior state value must be copied forward when neither variant is declared")
		assert.False(t, got.Null)
		assert.False(t, got.Unknown)
	}
}

// TestUnitPairedVariantModifier_CreateStaysUnknown is the Create-time
// companion to the previous test: with no prior state to copy from
// (AttributeState itself Unknown, as it is during Create), the plan must be
// left Unknown rather than fabricating a Null or zero value.
func TestUnitPairedVariantModifier_CreateStaysUnknown(t *testing.T) {
	ctx := context.Background()
	schema := pairedTestSchema()

	config := buildPairedTestConfig(
		t, ctx, schema, pairedTestModel{
			Interval: types.Int64{Null: true},
			Daily:    types.String{Null: true},
		},
	)
	// No prior state exists yet on Create.
	state := tfsdk.State{Schema: schema, Raw: config.Raw}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("interval"),
		Config:          config,
		State:           state,
		AttributeConfig: types.Int64{Null: true},
		AttributeState:  types.Int64{Unknown: true},
		AttributePlan:   types.Int64{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	pairedWith("daily").Modify(ctx, req, resp)

	assert.False(t, resp.Diagnostics.HasError(), "unexpected diagnostics: %+v", resp.Diagnostics)
	got, ok := resp.AttributePlan.(types.Int64)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.Int64, got %T", resp.AttributePlan) {
		assert.True(t, got.Unknown, "expected the plan to stay Unknown on Create (no prior state to copy from), got %+v", got)
	}
}

// TestUnitPairedVariantModifier_SiblingUnknownTreatedAsDeclared covers the
// last listed case: a sibling that is Unknown in config (e.g. it references
// another resource's not-yet-known output) still counts as "declared" per
// declaredInConfig's contract -- a practitioner wrote something there, even
// if its concrete value isn't resolvable yet -- so this attribute must still
// plan to Null rather than copying state forward.
func TestUnitPairedVariantModifier_SiblingUnknownTreatedAsDeclared(t *testing.T) {
	ctx := context.Background()
	schema := pairedTestSchema()

	config := buildPairedTestConfig(
		t, ctx, schema, pairedTestModel{
			Interval: types.Int64{Null: true},
			Daily:    types.String{Unknown: true}, // e.g. some_resource.attr, not yet resolved
		},
	)
	state := tfsdk.State{Schema: schema}
	if d := state.Set(
		ctx, &pairedTestModel{
			Interval: types.Int64{Value: 60},
			Daily:    types.String{Null: true},
		},
	); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("interval"),
		Config:          config,
		State:           state,
		AttributeConfig: types.Int64{Null: true},
		AttributeState:  types.Int64{Value: 60},
		AttributePlan:   types.Int64{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	pairedWith("daily").Modify(ctx, req, resp)

	assert.False(t, resp.Diagnostics.HasError(), "unexpected diagnostics: %+v", resp.Diagnostics)
	got, ok := resp.AttributePlan.(types.Int64)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.Int64, got %T", resp.AttributePlan) {
		assert.True(t, got.Null, "an Unknown-in-config sibling must still count as declared, planning this attribute Null, got %+v", got)
	}
}
