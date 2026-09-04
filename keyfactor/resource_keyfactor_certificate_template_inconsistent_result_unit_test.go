package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: allowed_requesters must be Computed.
//
// keyfactor_certificate_template.allowed_requesters was Optional but NOT
// Computed. When Update()'s preserveAllowedRequesters legitimately
// returns the server's real, non-null AllowedRequesters for an undeclared
// (planned-Null) allowed_requesters attribute, the terraform-plugin-framework
// requires the post-apply value to exactly equal the planned value for any
// attribute that isn't Computed -- so the framework rejected the corrected
// behavior as "Provider produced inconsistent result after apply", even
// though the data itself was now correct. The schema contract, not just the
// Update() logic, has to allow an undeclared value to resolve to something
// other than null.
//
// A related but distinct gap surfaced in the same harness run on
// display_name: it is Computed+UseStateForUnknown, but Command derives
// display_name from friendly_name (mirrors it back once one is configured).
// UseStateForUnknown pins display_name's planned value to the OLD state
// value on any Update() that doesn't declare display_name (which is every
// Update(), since it's Computed-only and can never be declared) -- but
// whenever friendly_name itself changes, the real post-apply display_name
// legitimately differs from that pinned old value, producing the same
// "inconsistent result after apply" class of error. This needed a
// friendly_name-aware plan modifier (displayNameFollowsFriendlyNameModifier),
// not a schema Computed/Optional change (display_name is already
// Computed-only and cannot be made Optional -- it isn't user-settable).
// ---------------------------------------------------------------------------

// asTemplateConfig / asTemplateState round-trip a
// KeyfactorCertificateTemplateState through a tfsdk.Plan (which has a .Set
// method Config/State lack in this framework version) and reuse the
// resulting Raw value to build a tfsdk.Config / tfsdk.State with the same
// underlying representation -- Plan/State/Config are all thin wrappers over
// {Raw tftypes.Value; Schema Schema}.
func asTemplateConfig(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateTemplateState) tfsdk.Config {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.Config{Schema: schema, Raw: p.Raw}
}

func asTemplateState(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateTemplateState) tfsdk.State {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.State{Schema: schema, Raw: p.Raw}
}

// TestUnitCertificateTemplateAllowedRequestersIsComputed is the schema-level
// regression test: allowed_requesters must be Computed (in addition to
// Optional) so that an undeclared value legally resolves to a non-null
// server value without the framework flagging "Provider produced
// inconsistent result after apply". Before the fix this attribute was
// Optional only.
func TestUnitCertificateTemplateAllowedRequestersIsComputed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := templateSchema(t, ctx)

	attr, ok := schema.Attributes["allowed_requesters"]
	if !ok {
		t.Fatal("schema has no allowed_requesters attribute")
	}
	if !attr.Optional {
		t.Error("allowed_requesters: expected Optional=true")
	}
	if !attr.Computed {
		t.Fatal(
			"allowed_requesters: expected Computed=true, got false -- without Computed, an undeclared " +
				"allowed_requesters plans to Null, and preserveAllowedRequesters legitimately returning the " +
				"server's real non-null value produces \"Provider produced inconsistent result after apply\"",
		)
	}
	if len(attr.PlanModifiers) == 0 {
		t.Error("allowed_requesters: expected a plan modifier (e.g. useStateOrNullModifier) so an undeclared value resolves to the prior state instead of staying Unknown")
	}
}

// TestUnitCertificateTemplateDisplayNameModifierPreservesWhenFriendlyNameUnchanged
// is the negative-space case: when friendly_name is not changing this apply
// (undeclared, or re-declared with its current value), the modifier should
// behave like UseStateForUnknown and carry forward the prior display_name --
// preserving "no changes" plan stability for the common case.
func TestUnitCertificateTemplateDisplayNameModifierPreservesWhenFriendlyNameUnchanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := templateSchema(t, ctx)

	tests := []struct {
		name           string
		configFriendly types.String
		stateFriendly  types.String
	}{
		{
			name:           "friendly_name undeclared in config",
			configFriendly: types.String{Null: true},
			stateFriendly:  types.String{Value: "Acme-Friendly"},
		},
		{
			name:           "friendly_name re-declared with its current value",
			configFriendly: types.String{Value: "Acme-Friendly"},
			stateFriendly:  types.String{Value: "Acme-Friendly"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config := blankTemplateState()
			config.FriendlyName = tc.configFriendly
			state := blankTemplateState()
			state.FriendlyName = tc.stateFriendly
			state.DisplayName = types.String{Value: "Acme-Friendly"}

			cfg := asTemplateConfig(t, ctx, schema, config)
			st := asTemplateState(t, ctx, schema, state)

			m := displayNameFollowsFriendlyNameModifier{}
			req := tfsdk.ModifyAttributePlanRequest{
				Config:          cfg,
				State:           st,
				AttributeConfig: types.String{Null: true}, // display_name is Computed-only; config is always null
				AttributeState:  types.String{Value: "Acme-Friendly"},
			}
			resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

			m.Modify(ctx, req, resp)

			got, ok := resp.AttributePlan.(types.String)
			if !ok {
				t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
			}
			if got.Unknown || got.Null || got.Value != "Acme-Friendly" {
				t.Errorf(
					"display_name plan = %+v, want the prior state value \"Acme-Friendly\" preserved "+
						"(friendly_name is not changing this apply)", got,
				)
			}
		})
	}
}

// TestUnitCertificateTemplateDisplayNameModifierLeavesUnknownWhenFriendlyNameChanges
// is the root-bug regression test: when friendly_name IS changing this apply
// (newly declared or declared with a different value), display_name -- which
// Command derives from friendly_name -- must be left Unknown rather than
// pinned to the stale prior state value. Pinning it would make the
// framework reject the real post-apply (changed) display_name as
// "Provider produced inconsistent result after apply".
func TestUnitCertificateTemplateDisplayNameModifierLeavesUnknownWhenFriendlyNameChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := templateSchema(t, ctx)

	config := blankTemplateState()
	config.FriendlyName = types.String{Value: "New-Friendly-Name"}
	state := blankTemplateState()
	state.FriendlyName = types.String{Value: "Old-Friendly-Name"}
	state.DisplayName = types.String{Value: "Old-Friendly-Name"}

	cfg := asTemplateConfig(t, ctx, schema, config)
	st := asTemplateState(t, ctx, schema, state)

	m := displayNameFollowsFriendlyNameModifier{}
	req := tfsdk.ModifyAttributePlanRequest{
		Config:          cfg,
		State:           st,
		AttributeConfig: types.String{Null: true},
		AttributeState:  types.String{Value: "Old-Friendly-Name"},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: types.String{Unknown: true}}

	m.Modify(ctx, req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if !ok {
		t.Fatalf("resp.AttributePlan is not types.String: %T", resp.AttributePlan)
	}
	if !got.Unknown {
		t.Errorf(
			"display_name plan = %+v, want Unknown (friendly_name is changing this apply, so the stale "+
				"prior display_name value must not be pinned as the planned value) -- this reproduces the "+
				"root bug: pinning a stale value here means the real, changed display_name Command returns "+
				"after Update() can never match the plan, producing \"Provider produced inconsistent result "+
				"after apply\"", got,
		)
	}
}
