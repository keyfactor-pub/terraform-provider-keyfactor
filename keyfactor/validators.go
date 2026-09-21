package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// RequiresReplaceIfPreviouslySet returns an AttributePlanModifier that only
// forces resource replacement when the attribute had a known, non-null value
// in prior state AND that value differs from the planned value.
//
// Unlike tfsdk.RequiresReplace(), this modifier does NOT trigger replacement
// when the prior state is null (e.g. after a terraform import).  This is the
// correct behaviour for write-only enrollment parameters such as
// certificate_template and certificate_enrollment_pattern: after import those
// fields are null because the server does not return them; adding a value in
// the next plan should not force re-enrollment.
func RequiresReplaceIfPreviouslySet() tfsdk.AttributePlanModifier {
	return tfsdk.RequiresReplaceIf(
		func(_ context.Context, state, _ attr.Value, _ path.Path) (bool, diag.Diagnostics) {
			// Only require replacement when the attribute was already set in state.
			return !state.IsNull() && !state.IsUnknown(), nil
		},
		"Requires replacement only when changing a previously set value (not when first setting a value after import).",
		"Requires replacement only when changing a previously set value (not when first setting a value after import).",
	)
}

// conflictsWithAttrValidator rejects this attribute when the named sibling
// attribute is also set. Used to prevent meaningless combinations such as
// specifying key_type/key_size/curve alongside a CSR (the key is already
// embedded in the CSR and these fields would be silently ignored).
//
// The optional message field provides extra context appended to the error
// description. When empty, a default CSR-specific message is used to preserve
// backward compatibility for existing callers.
type conflictsWithAttrValidator struct {
	otherAttr string
	message   string // optional; defaults to CSR key-type context when empty
}

func (v conflictsWithAttrValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("Cannot be set when `%s` is also set", v.otherAttr)
}

func (v conflictsWithAttrValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v conflictsWithAttrValidator) Validate(
	ctx context.Context,
	req tfsdk.ValidateAttributeRequest,
	resp *tfsdk.ValidateAttributeResponse,
) {
	if req.AttributeConfig.IsNull() || req.AttributeConfig.IsUnknown() {
		return
	}
	var otherVal attr.Value
	diags := req.Config.GetAttribute(ctx, path.Root(v.otherAttr), &otherVal)
	resp.Diagnostics.Append(diags...)
	if otherVal != nil && !otherVal.IsNull() && !otherVal.IsUnknown() {
		extra := "The key type is determined by the CSR."
		if v.message != "" {
			extra = v.message
		}
		resp.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Conflicting Attributes",
			fmt.Sprintf(
				"`%s` cannot be set when `%s` is also set. %s",
				req.AttributePath.String(),
				v.otherAttr,
				extra,
			),
		)
	}
}

// int64AtLeastValidator rejects values less than min. Null and unknown values
// are allowed (the attribute is optional). This avoids adding an external
// dependency for a simple numeric bound check.
type int64AtLeastValidator struct {
	min int64
}

func (v int64AtLeastValidator) Description(_ context.Context) string {
	return fmt.Sprintf("Value must be at least %d", v.min)
}

func (v int64AtLeastValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v int64AtLeastValidator) Validate(
	_ context.Context,
	req tfsdk.ValidateAttributeRequest,
	resp *tfsdk.ValidateAttributeResponse,
) {
	val, ok := req.AttributeConfig.(types.Int64)
	if !ok || val.IsNull() || val.IsUnknown() {
		return
	}
	if val.Value < v.min {
		resp.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Value Out of Range",
			fmt.Sprintf("Value must be at least %d, got %d.", v.min, val.Value),
		)
	}
}

// atLeastOneOfValidator validates that at least one of this attribute or
// the other named attribute is set. Both being set is allowed : the API
// handles precedence (enrollment pattern takes precedence over template).
type atLeastOneOfValidator struct {
	otherAttr string
}

func (v atLeastOneOfValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("At least one of this attribute or `%s` must be set", v.otherAttr)
}

func (v atLeastOneOfValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v atLeastOneOfValidator) Validate(
	ctx context.Context,
	req tfsdk.ValidateAttributeRequest,
	resp *tfsdk.ValidateAttributeResponse,
) {
	// An attribute is considered "set" only if it is non-null AND, for string
	// attributes, non-empty. Unknown values (e.g. locals derived from variables
	// during `terraform validate`) are treated as "set" because we cannot know
	// their final value yet — rejecting them here would produce false positives
	// during validate when the actual apply value will be non-empty.
	strVal, ok := req.AttributeConfig.(types.String)
	attrVal := !req.AttributeConfig.IsNull() && (req.AttributeConfig.IsUnknown() || !ok || strVal.Value != "")

	var otherAttrValue attr.Value
	diags := req.Config.GetAttribute(ctx, path.Root(v.otherAttr), &otherAttrValue)
	resp.Diagnostics.Append(diags...)
	otherStr, otherIsStr := otherAttrValue.(types.String)
	otherVal := otherAttrValue != nil && !otherAttrValue.IsNull() && (otherAttrValue.IsUnknown() || !otherIsStr || otherStr.Value != "")

	if !attrVal && !otherVal {
		resp.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Missing Required Attribute",
			fmt.Sprintf(
				"At least one of `%s` or `%s` must be set.",
				req.AttributePath.String(),
				v.otherAttr,
			),
		)
	}
}
