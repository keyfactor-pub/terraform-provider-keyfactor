package keyfactor

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// This file holds the shared "server-managed unless declared" attribute
// contract used across resources in this provider (currently
// template_role_binding's KeyUsage handling, security_role's Permissions,
// security_identity's Roles, and certificate_authority's schedules /
// allowed_requesters). The contract, in full:
//
//  1. Omitted from config (Config value Null) -> unmanaged/preserve: never
//     send a clearing value; Read still writes server truth to state (drift
//     visible, never silently "corrected").
//  2. Declared -> managed: plan diffs surface drift; Update enforces config.
//  3. Explicit empty sentinel ([]/""/false/0/...) -> declarative clear.
//  4. Sentinel stability: post-apply state keeps the declared sentinel (not
//     server-null); Read keeps the sentinel when server reports absent AND
//     prior state holds the sentinel; Read writes server truth when a real
//     value appears.
//  5. Declared-ness is ALWAYS keyed on request.Config (plan modifiers rewrite
//     Plan, never Config) -- see declaredInConfig below.
//
// declaredInConfig is the single predicate every resource in this provider
// should use to answer "did the practitioner declare this attribute". Reference
// implementations that established this invariant ad hoc before this helper
// existed: identityRolesDeclared (resource_keyfactor_security_identity.go) and
// buildSecurityRoleUpdateArg's doc comment (resource_keyfactor_security_role.go).

// declaredInConfig reports whether a Config-sourced attribute value was
// actually written by the practitioner, as opposed to being genuinely absent.
//
// v MUST come from request.Config (tfsdk.Config.Get / GetAttribute) -- NEVER
// from request.Plan. Optional+Computed attributes commonly carry a plan
// modifier (tfsdk.UseStateForUnknown, pairedVariantModifier below,
// useStateOrNullModifier) that copies the prior state's value forward onto
// Plan precisely when the attribute is undeclared, so the CLI doesn't show
// spurious "(known after apply)" noise on every unrelated plan. Once such a
// modifier has run, Plan.<Attr> is no longer null for an undeclared
// attribute, so checking Plan here would misclassify "undeclared, copied
// forward from state" as "declared." Config is never touched by plan
// modifiers, so it is the only reliable signal of practitioner intent.
//
// An Unknown value (e.g. a reference to another resource/data source output
// that hasn't resolved yet) counts as declared: the practitioner wrote
// something into this attribute -- even though its concrete value isn't
// known yet -- so it is management intent, not omission.
func declaredInConfig(v attr.Value) bool {
	return v != nil && !v.IsNull()
}

// pairedVariantModifier is a plan modifier for a pair of mutually-exclusive
// attributes ("variants") where declaring one is meant to implicitly clear
// the other -- e.g. an interval-based schedule vs. a daily-time-based
// schedule for the same underlying setting. It replaces tfsdk.UseStateForUnknown
// on each half of such a pair.
//
// Modify runs in this order:
//  1. If the plan for THIS attribute is already known (not Unknown), the
//     config declared it directly (including an explicit clear sentinel) --
//     leave it alone.
//  2. Otherwise, if the sibling variant is declared in CONFIG, this attribute
//     is being superseded by the variant switch: plan it explicitly Null so
//     the resulting diff (e.g. interval 60 -> null) is truthful, instead of
//     resurrecting the prior value the way a bare UseStateForUnknown would.
//  3. Otherwise (neither this attribute nor its sibling is declared), fall
//     back to useStateOrNullModifier semantics: copy the prior state forward
//     (null stays null, a known value stays known), leaving Unknown only when
//     there is no prior state to copy from (i.e. on Create).
//
// See useStateOrNullModifier (resource_keyfactor_certificate_template.go) and
// formatDependentModifier (resource_keyfactor_certificate.go) for the two
// precedents this generalizes: the former is exactly step 3 in isolation, the
// latter is the same "does a sibling attribute's config value change the
// outcome" shape that step 2 generalizes beyond a boolean/enum discriminator
// to "is the sibling itself declared."
type pairedVariantModifier struct {
	sibling string
}

// pairedWith constructs a pairedVariantModifier naming the sibling attribute
// (by schema attribute name, at the same nesting level as the attribute this
// modifier is attached to) that this attribute's variant is mutually
// exclusive with.
func pairedWith(sibling string) pairedVariantModifier {
	return pairedVariantModifier{sibling: sibling}
}

func (m pairedVariantModifier) Description(_ context.Context) string {
	return "Preserves state for this attribute's variant unless its paired variant \"" + m.sibling + "\" is declared in config, in which case this attribute plans to null."
}

func (m pairedVariantModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m pairedVariantModifier) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if resp.AttributePlan == nil {
		return
	}

	// Step 1: the config already declared this attribute (including an
	// explicit clear sentinel) -- the plan is already known, leave it.
	if !resp.AttributePlan.IsUnknown() {
		return
	}

	// Step 2: if the sibling variant is declared in Config, this attribute is
	// being superseded by the variant switch -- plan it Null rather than
	// resurrecting the prior state value.
	siblingPath := req.AttributePath.ParentPath().AtName(m.sibling)
	siblingConfig, diags := getConfigAttributeValue(ctx, req.Config, siblingPath)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}
	if declaredInConfig(siblingConfig) {
		nullValue, err := nullValueOfType(ctx, resp.AttributePlan)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				req.AttributePath,
				"Error constructing paired-variant null plan value",
				err.Error(),
			)
			return
		}
		resp.AttributePlan = nullValue
		return
	}

	// Step 3: neither this attribute nor its sibling is declared --
	// useStateOrNullModifier semantics: copy state forward (null stays null,
	// known stays known), leaving Unknown when state itself is Unknown (no
	// prior state to copy from, i.e. Create).
	useStateOrNullModifier{}.Modify(ctx, req, resp)
}

// getConfigAttributeValue reads a single attribute's value out of a
// tfsdk.Config generically (works for any attr.Value-implementing type --
// types.Int64, types.String, types.List, ...) by populating a *attr.Value
// target, which tfsdk.Config.GetAttribute/ValueAs special-cases to mean "give
// me the value as-is, don't try to convert to a concrete Go type."
func getConfigAttributeValue(ctx context.Context, config tfsdk.Config, p path.Path) (attr.Value, diag.Diagnostics) {
	var v attr.Value
	diags := config.GetAttribute(ctx, p, &v)
	return v, diags
}

// nullValueOfType builds a null attr.Value sharing the same underlying type
// as an existing (possibly Unknown) attr.Value, generically -- works for any
// attr.Type via the ValueFromTerraform/TerraformType round-trip, so this
// modifier does not need a type switch to support both types.Int64 and
// types.String (or any other attribute type) attributes.
func nullValueOfType(ctx context.Context, like attr.Value) (attr.Value, error) {
	attrType := like.Type(ctx)
	return attrType.ValueFromTerraform(ctx, tftypes.NewValue(attrType.TerraformType(ctx), nil))
}
