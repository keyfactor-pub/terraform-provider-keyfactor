package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

type xorValidator struct {
	otherAttr string
}

func (v xorValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("Exactly one of this attribute or `%s` must be set", v.otherAttr)
}

func (v xorValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v xorValidator) Validate(
	ctx context.Context,
	req tfsdk.ValidateAttributeRequest,
	resp *tfsdk.ValidateAttributeResponse,
) {
	attrVal := !req.AttributeConfig.IsNull()

	var otherAttrValue attr.Value
	diags := req.Config.GetAttribute(ctx, path.Root(v.otherAttr), &otherAttrValue)
	resp.Diagnostics.Append(diags...)
	otherVal := otherAttrValue != nil && !otherAttrValue.IsNull()

	if (attrVal && otherVal) || (!attrVal && !otherVal) {
		resp.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Invalid Attribute Combination",
			fmt.Sprintf(
				"Exactly one of `%s` or `%s` must be set, but not both or neither.",
				req.AttributePath.String(),
				v.otherAttr,
			),
		)
	}
}
