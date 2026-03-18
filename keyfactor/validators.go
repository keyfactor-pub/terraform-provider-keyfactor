package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

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
