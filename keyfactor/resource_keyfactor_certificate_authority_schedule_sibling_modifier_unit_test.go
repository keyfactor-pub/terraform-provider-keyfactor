package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests — full-review round 1 finding #2 (correctness, high):
//
// All six schedule attributes (full_scan/incremental_scan/threshold_check x
// interval/daily) were Optional+Computed with only a bare
// tfsdk.UseStateForUnknown(). Switching schedule variants -- e.g. a CA with
// full_scan_interval_minutes=60 in state, config changed to declare only
// full_scan_daily_time -- always failed apply with "Provider produced
// inconsistent result after apply": core's proposed plan resolves the
// now-undeclared full_scan_interval_minutes to Unknown (Computed + null
// config), and a bare UseStateForUnknown blindly pins that Unknown back to
// the OLD known value (60), having no way to know a sibling attribute is
// taking over. The recorded plan ends up with BOTH full_scan_interval_minutes
// =60 AND full_scan_daily_time="<new>" at once. preserveCAUpdateFields (see
// resource_keyfactor_certificate_authority_schedule_unit_test.go) nulls the
// stale sibling, but only inside Update()'s own local plan copy -- long
// after PlanResourceChange already recorded the plan Terraform core checks
// the final applied state against.
//
// The fix (scheduleSiblingModifier, resource_keyfactor_certificate_authority.go)
// reads the sibling attribute's CONFIG value at plan time and nulls this
// attribute instead of resurrecting its stale state value whenever the
// sibling is taking over.
// ---------------------------------------------------------------------------

// TestUnitCABareUseStateForUnknownResurrectsSiblingOnVariantSwitch is the
// concrete "red" reproduction, run against the actual pre-fix modifier
// (tfsdk.UseStateForUnknownModifier{}, what every schedule attribute used
// before this change) rather than a hand-edited schema: switching from an
// Interval schedule to a Daily one, the bare modifier pins the plan back to
// the stale Interval value because it has no notion of a sibling attribute.
func TestUnitCABareUseStateForUnknownResurrectsSiblingOnVariantSwitch(t *testing.T) {
	t.Parallel()

	// State: Interval-shaped schedule (60 minutes), no Daily value.
	// Config: switches to Daily only -- full_scan_interval_minutes undeclared.
	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.Int64{Value: 60},
		AttributeConfig: types.Int64{Null: true}, // undeclared in the new config
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Unknown: true}}

	tfsdk.UseStateForUnknownModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.Int64)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.Int64: %T", resp.AttributePlan)
	}
	if got.Null || got.Value != 60 {
		t.Fatalf(
			"reproduces the bug: the pre-fix bare UseStateForUnknown modifier resurrected the stale "+
				"full_scan_interval_minutes=60 from state even though the sibling full_scan_daily_time is "+
				"taking over this apply -- got Null=%v Value=%v, want the stale value resurrected (Null=false, "+
				"Value=60) to prove this really is the root cause finding #2 fixes",
			got.Null, got.Value,
		)
	}
}

// TestUnitCAScheduleSiblingModifierNullsStaleSiblingOnVariantSwitch is the
// direct "green" regression test: switching from Interval to Daily (and the
// symmetric Daily-to-Interval direction) must null the stale sibling's plan
// instead of resurrecting it from state.
func TestUnitCAScheduleSiblingModifierNullsStaleSiblingOnVariantSwitch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	t.Run("interval to daily", func(t *testing.T) {
		t.Parallel()

		// Config declares only full_scan_daily_time -- full_scan_interval_minutes
		// is undeclared (the sibling taking over).
		config := blankCAConfig()
		config.FullScanDailyTime = types.String{Value: "07:00:00"}
		cfg := asConfig(t, ctx, schema, config)

		req := tfsdk.ModifyAttributePlanRequest{
			AttributeState:  types.Int64{Value: 60}, // stale prior Interval value
			AttributeConfig: types.Int64{Null: true},
			Config:          cfg,
		}
		resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Unknown: true}}

		m := scheduleSiblingModifier{siblingPath: path.Root("full_scan_daily_time"), nullValue: types.Int64{Null: true}}
		m.Modify(ctx, req, resp)

		got, ok := resp.AttributePlan.(types.Int64)
		if !ok {
			t.Fatalf("resp.AttributePlan is not types.Int64: %T", resp.AttributePlan)
		}
		if !got.Null {
			t.Fatalf(
				"full_scan_interval_minutes plan = %+v, want Null -- the sibling full_scan_daily_time is "+
					"declared in config and taking over this apply, so this attribute's stale prior-state "+
					"value (60) must not be resurrected onto the plan (that is exactly what produces "+
					"\"Provider produced inconsistent result after apply\" once Update() nulls it too late)",
				got,
			)
		}
	})

	t.Run("daily to interval", func(t *testing.T) {
		t.Parallel()

		// Config declares only full_scan_interval_minutes -- full_scan_daily_time
		// is undeclared (the sibling taking over).
		config := blankCAConfig()
		config.FullScanIntervalMinutes = types.Int64{Value: 30}
		cfg := asConfig(t, ctx, schema, config)

		req := tfsdk.ModifyAttributePlanRequest{
			AttributeState:  types.String{Value: "00:00:00"}, // stale prior Daily value
			AttributeConfig: types.String{Null: true},
			Config:          cfg,
		}
		resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

		m := scheduleSiblingModifier{siblingPath: path.Root("full_scan_interval_minutes"), nullValue: types.String{Null: true}}
		m.Modify(ctx, req, resp)

		got, ok := resp.AttributePlan.(types.String)
		if !ok {
			t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
		}
		if !got.Null {
			t.Fatalf(
				"full_scan_daily_time plan = %+v, want Null -- the sibling full_scan_interval_minutes is "+
					"declared in config and taking over this apply, so this attribute's stale prior-state "+
					"value (\"00:00:00\") must not be resurrected onto the plan",
				got,
			)
		}
	})
}

// TestUnitCAScheduleSiblingModifierCarriesForwardWhenNeitherDeclared is the
// negative-space companion: when config declares NEITHER member of a pair,
// the modifier must behave exactly like plain UseStateForUnknown and carry
// the prior state value forward -- there is no variant switch to reconcile.
func TestUnitCAScheduleSiblingModifierCarriesForwardWhenNeitherDeclared(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig() // neither full_scan_interval_minutes nor full_scan_daily_time declared
	cfg := asConfig(t, ctx, schema, config)

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.String{Value: "07:00:00"},
		AttributeConfig: types.String{Null: true},
		Config:          cfg,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

	m := scheduleSiblingModifier{siblingPath: path.Root("full_scan_interval_minutes"), nullValue: types.String{Null: true}}
	m.Modify(ctx, req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
	}
	if got.Null || got.Unknown || got.Value != "07:00:00" {
		t.Errorf(
			"full_scan_daily_time plan = %+v, want the prior state value \"07:00:00\" carried forward "+
				"(neither schedule variant is declared in config, so there is nothing to reconcile -- ordinary "+
				"UseStateForUnknown semantics apply)", got,
		)
	}
}

// TestUnitCAScheduleSiblingModifierLeavesUnknownWhenSiblingItselfUnknown
// covers the conservative branch: if the sibling's own config value is
// Unknown (e.g. it references another resource's attribute not yet applied
// this run), the modifier cannot yet tell whether the sibling is taking
// over, so it must leave this attribute Unknown too rather than guess.
func TestUnitCAScheduleSiblingModifierLeavesUnknownWhenSiblingItselfUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	// Build a config whose full_scan_daily_time is Unknown by round-tripping a
	// plan with an Unknown value through the schema, then reusing the Raw
	// representation as Config -- mirroring asConfig's own technique.
	config := blankCAConfig()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	if d := p.SetAttribute(ctx, path.Root("full_scan_daily_time"), types.String{Unknown: true}); d.HasError() {
		t.Fatalf("test setup: Plan.SetAttribute returned diagnostics: %+v", d)
	}
	cfg := tfsdk.Config{Schema: schema, Raw: p.Raw}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.Int64{Value: 60},
		AttributeConfig: types.Int64{Null: true},
		Config:          cfg,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Unknown: true}}

	m := scheduleSiblingModifier{siblingPath: path.Root("full_scan_daily_time"), nullValue: types.Int64{Null: true}}
	m.Modify(ctx, req, resp)

	got, ok := resp.AttributePlan.(types.Int64)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.Int64: %T", resp.AttributePlan)
	}
	if !got.Unknown {
		t.Errorf(
			"full_scan_interval_minutes plan = %+v, want Unknown -- the sibling full_scan_daily_time's own "+
				"config value is itself Unknown (depends on some other not-yet-known value this apply), so "+
				"whether it is taking over cannot yet be determined; guessing either way risks the same "+
				"inconsistent-result class this modifier exists to prevent", got,
		)
	}
}

// TestUnitCAScheduleSiblingModifierNoOpWhenSelfDeclared documents (and locks
// in) the early-return guard shared with tfsdk.UseStateForUnknownModifier:
// when this attribute's OWN plan is already known (because config declared
// it directly), the modifier must not touch it at all -- it only ever
// intervenes on an Unknown plan.
func TestUnitCAScheduleSiblingModifierNoOpWhenSelfDeclared(t *testing.T) {
	t.Parallel()

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.Int64{Value: 60},
		AttributeConfig: types.Int64{Value: 45},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.Int64{Value: 45}} // already known -- config declared it

	m := scheduleSiblingModifier{siblingPath: path.Root("full_scan_daily_time"), nullValue: types.Int64{Null: true}}
	m.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.Int64)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.Int64: %T", resp.AttributePlan)
	}
	if got.Null || got.Unknown || got.Value != 45 {
		t.Errorf("full_scan_interval_minutes plan = %+v, want the declared config value 45 left untouched", got)
	}
}

// TestUnitCAScheduleAttributesUseSiblingModifier is the schema-level
// regression test: all six schedule attributes must be wired to
// scheduleSiblingModifier (pointed at their correct sibling path), not a bare
// tfsdk.UseStateForUnknown(), so the variant-switch reconciliation above
// actually runs during a real plan.
func TestUnitCAScheduleAttributesUseSiblingModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	pairs := []struct {
		attrName    string
		siblingName string
	}{
		{"full_scan_interval_minutes", "full_scan_daily_time"},
		{"full_scan_daily_time", "full_scan_interval_minutes"},
		{"incremental_scan_interval_minutes", "incremental_scan_daily_time"},
		{"incremental_scan_daily_time", "incremental_scan_interval_minutes"},
		{"threshold_check_interval_minutes", "threshold_check_daily_time"},
		{"threshold_check_daily_time", "threshold_check_interval_minutes"},
	}

	for _, p := range pairs {
		p := p
		t.Run(p.attrName, func(t *testing.T) {
			t.Parallel()
			schemaAttr, ok := schema.Attributes[p.attrName]
			if !ok {
				t.Fatalf("schema has no %s attribute", p.attrName)
			}
			if len(schemaAttr.PlanModifiers) != 1 {
				t.Fatalf("%s: want exactly 1 plan modifier, got %d", p.attrName, len(schemaAttr.PlanModifiers))
			}
			m, ok := schemaAttr.PlanModifiers[0].(scheduleSiblingModifier)
			if !ok {
				t.Fatalf(
					"%s: plan modifier is %T, want scheduleSiblingModifier -- a bare tfsdk.UseStateForUnknown() "+
						"here reproduces finding #2: switching schedule variants would resurrect the stale "+
						"sibling value onto the plan, failing apply with \"Provider produced inconsistent "+
						"result after apply\"", p.attrName, schemaAttr.PlanModifiers[0],
				)
			}
			if m.siblingPath.String() != path.Root(p.siblingName).String() {
				t.Errorf("%s: modifier siblingPath = %q, want %q", p.attrName, m.siblingPath.String(), path.Root(p.siblingName).String())
			}
		})
	}
}
