package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// conflictsWithAttrValidator rejects this attribute when the named sibling
// attribute is also set. Used to prevent meaningless combinations such as
// specifying key_type/key_size/curve alongside a CSR (the key is already
// embedded in the CSR and these fields would be silently ignored).
type conflictsWithAttrValidator struct {
	otherAttr string
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
		resp.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Conflicting Attributes",
			fmt.Sprintf(
				"`%s` cannot be set when `%s` is also set. The key type is determined by the CSR.",
				req.AttributePath.String(),
				v.otherAttr,
			),
		)
	}
}

// atLeastOneOfValidator validates that at least one of this attribute or
// the other named attribute is set. Both being set is allowed — the API
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
	attrVal := !req.AttributeConfig.IsNull()

	var otherAttrValue attr.Value
	diags := req.Config.GetAttribute(ctx, path.Root(v.otherAttr), &otherAttrValue)
	resp.Diagnostics.Append(diags...)
	otherVal := otherAttrValue != nil && !otherAttrValue.IsNull()

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
