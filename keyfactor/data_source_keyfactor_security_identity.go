package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceSecurityIdentityType struct{}

func (r dataSourceSecurityIdentityType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
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
				Type: types.ListType{
					ElemType: types.StringType,
				},
				Optional:    true,
				Description: "An array containing the role IDs that the identity is attached to.",
			},
			"id": {
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

func (r dataSourceSecurityIdentityType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceSecurityIdentity{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceSecurityIdentity struct {
	p provider
}

func (r dataSourceSecurityIdentity) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	var state SecurityIdentity
	diags := request.Config.Get(ctx, &state)
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
		if accountName == identity.AccountName {
			tflog.Info(ctx, fmt.Sprintf("Found identity with account name: %s", accountName))

			var validRoles []attr.Value
			var validRolesInterface []interface{}
			for _, role := range identity.Roles {
				//validRoles = append(validRoles.Elems, role.Name.Value)
				tflog.Info(ctx, fmt.Sprintf("Adding role: %s", role.Name))
				tflog.Debug(ctx, fmt.Sprintf("Looking up role %s in Keyfactor", role.Name))

				kfRole, roleLookupErr := r.p.client.GetSecurityRole(role.Name)
				if roleLookupErr != nil || kfRole == nil {
					tflog.Warn(ctx, fmt.Sprintf("Error looking up role %v on Keyfactor.", role))
					response.Diagnostics.AddWarning(
						"Error looking up role on Keyfactor.",
						fmt.Sprintf("Error looking up role '%s' on Keyfactor. '%s' will not have role '%s'.", role.Name, state.AccountName.Value, role.Name),
					)
					continue
				}
				validRoles = append(validRoles, types.String{Value: fmt.Sprintf("%s", role.Name)})
				validRolesInterface = append(validRolesInterface, kfRole.Id)
			}

			state = SecurityIdentity{
				ID:           types.Int64{Value: int64(identity.Id)},
				AccountName:  types.String{Value: identity.AccountName},
				IdentityType: types.String{Value: identity.IdentityType},
				Roles:        types.List{Elems: validRoles, ElemType: types.StringType},
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
