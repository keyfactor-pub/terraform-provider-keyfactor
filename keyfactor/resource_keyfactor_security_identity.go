package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceSecurityIdentityType struct{}

func (r resourceSecurityIdentityType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"account_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.RequiresReplace(),
				},
			},
			"roles": {
				Type:        types.SetType{ElemType: types.StringType},
				Computed:    true,
				Description: "An array containing the role IDs that the identity is attached to.",
			},
			"identity_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer containing the Keyfactor Command identifier for the security identity.",
			},
			"identity_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the type of identity—User or Group.",
			},
			"valid": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that indicates whether the security identity's audit XML is valid (true) or not (false). A security identity may become invalid if Keyfactor Command determines that it appears to have been tampered with.",
			},
		},
	}, nil
}

// New resource instance
func (r resourceSecurityIdentityType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceSecurityIdentity{
		p: *(p.(*provider)),
	}, nil
}

type resourceSecurityIdentity struct {
	p provider
}

func (r resourceSecurityIdentity) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	var state SecurityIdentity
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on security identity resource")
	identityId := state.ID.Value
	accountName := state.AccountName.Value
	tflog.SetField(ctx, "identity_id", identityId)

	identities, err := r.p.client.GetSecurityIdentities()
	if err != nil {
		response.Diagnostics.AddError("Error listing identities from Keyfactor.", "Error reading identities: "+err.Error())
	}

	for _, identity := range identities {
		if int64(identity.Id) == identityId {
			tflog.Info(ctx, fmt.Sprintf("Found identity with id: %s", identityId))
			break
		}
		if accountName == identity.AccountName {
			tflog.Info(ctx, fmt.Sprintf("Found identity with account name: %s", accountName))
			state = SecurityIdentity{
				ID:           types.Int64{Value: int64(identity.Id)},
				AccountName:  types.String{Value: identity.AccountName},
				IdentityType: types.String{Value: identity.IdentityType},
				Valid:        types.Bool{Value: identity.Valid},
			}
			break
		}

	}

	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityIdentity) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	//TODO implement me
	panic("implement me")
}

func (r resourceSecurityIdentity) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	//TODO implement me
	panic("implement me")
}

func (r resourceSecurityIdentity) Create(ctx context.Context, req tfsdk.CreateResourceRequest, resp *tfsdk.CreateResourceResponse) {

}

func (r resourceSecurityIdentity) ImportState(ctx context.Context, req tfsdk.ImportResourceStateRequest, resp *tfsdk.ImportResourceStateResponse) {
	tfsdk.ResourceImportStatePassthroughID(ctx, path.Root("account_name"), req, resp)

}
