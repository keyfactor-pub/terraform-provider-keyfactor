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

type dataSourceOAuthSecurityRoleType struct{}

func (r dataSourceOAuthSecurityRoleType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Internal ID of the role.",
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Description of the security role",
			},
			"description": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the description of the OAuth security claim in Keyfactor",
			},
			"email_address": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Email address associated with the OAuth security role in Keyfactor",
			},
			"immutable": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Indicates whether the OAuth security role in Keyfactor is immutable. If true, the role cannot be modified or deleted. This is typically used for system-defined roles that are essential for the operation of Keyfactor.",
			},
			"permission_set_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "The ID of the permission set associated with the OAuth security role in Keyfactor. This is used to identify the permissions associated with the role.",
			},
			"permissions": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "A list of permissions associated with the OAuth security role in Keyfactor. This will return a list of permissions that are associated with the OAuth security role. This is used to identify the permissions associated with the role.",
			},
			"claims": {
				Attributes: tfsdk.ListNestedAttributes(
					map[string]tfsdk.Attribute{
						"id": {
							Type:        types.Int64Type,
							Computed:    true,
							Description: "The ID of the OAuth security claim in Keyfactor",
						},
						"description": {
							Type:        types.StringType,
							Computed:    true,
							Description: "The description of the OAuth security claim in Keyfactor",
						},
						"claim_type": {
							Type:        types.StringType,
							Computed:    true,
							Description: "The claim type of the OAuth security claim in Keyfactor",
						},
						"claim_value": {
							Type:        types.StringType,
							Computed:    true,
							Description: "The claim value of the OAuth security claim in Keyfactor",
						},
						"provider_authentication_scheme": {
							Type:        types.StringType,
							Computed:    true,
							Description: "The provider authentication scheme of the OAuth security claim in Keyfactor",
						},
						"provider": {
							Type: types.ObjectType{
								AttrTypes: OAuthSecurityClaimAuthenticationProviderType,
							},
							Computed:    true,
							Description: "An object containing the provider of the OAuth security claim in Keyfactor",
						},
					},
				),
				Computed:    true,
				Description: "A list of OAuth security claims associated with the OAuth security role in Keyfactor",
			},
		},
		Description: "Reads an existing security role from Keyfactor Command using the V2 `/Security/Roles` API. Compatible with Keyfactor Command versions 11+.",
	}, nil
}

func (r dataSourceOAuthSecurityRoleType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceOauthSecurityRole{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceOauthSecurityRole struct {
	p provider
}

func (r dataSourceOauthSecurityRole) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	tflog.Info(ctx, "Read called on security remoteState resource")
	var state OAuthSecurityRole

	tflog.Debug(ctx, "Read called on OAuth security role data source.")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	roleName := state.Name.Value
	role, err := GetSecurityRoleByName(ctx, r.p.sdkClient, roleName)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading OAuth security role",
			"Unable to find OAuth security role with name: "+roleName+". Error: "+err.Error(),
		)
		return
	}

	roleId := int32(*role.Id)

	tflog.Debug(ctx, "Data source was able to identify OAuth security role from remote source")
	tflog.Debug(ctx, fmt.Sprintf("Querying security role by ID %d", roleId))

	api := r.p.sdkClient.V2.SecurityRolesApi
	remoteState, _, err := api.NewGetSecurityRolesByIdRequest(ctx, int32(*role.Id)).Execute()
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading OAuth security role",
			fmt.Sprintf("Unable to query OAuth security role %s by ID %d. Err: %s", roleName, roleId, err.Error()),
		)
	}

	var permissionValues []attr.Value
	for _, perm := range remoteState.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		permissionValues = append(permissionValues, types.String{Value: perm})
	}

	var claims []OAuthSecurityClaim
	for _, claim := range remoteState.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))
		provider := *claim.Provider
		temp := OAuthSecurityClaim{
			ID:                           types.Int64{Value: int64(*claim.Id)},
			Description:                  types.String{Value: *claim.Description.Get()},
			ClaimType:                    types.String{Value: *claim.ClaimType.Get()},
			ClaimValue:                   types.String{Value: *claim.ClaimValue.Get()},
			ProviderAuthenticationScheme: types.String{Value: *provider.AuthenticationScheme.Get()},
			Provider:                     mapAuthenticationProviderType(*provider.Id, *provider.AuthenticationScheme.Get(), *provider.DisplayName.Get()),
		}
		claims = append(claims, temp)
	}

	tflog.Debug(ctx, "Data source was able to resource OAuth security role from remote source using ID")

	var result = OAuthSecurityRole{
		ID:              types.Int64{Value: int64(*remoteState.Id)},
		Name:            types.String{Value: *remoteState.Name.Get()},
		Description:     types.String{Value: *remoteState.Description.Get()},
		EmailAddress:    types.String{Value: *remoteState.EmailAddress.Get()},
		Immutable:       types.Bool{Value: *remoteState.Immutable},
		Permissions:     types.List{ElemType: types.StringType, Elems: permissionValues},
		PermissionSetId: types.String{Value: *remoteState.PermissionSetId},
		Claims:          claims,
	}

	tflog.Debug(ctx, "Saving OAuth security role data source information into state...")

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role data source read successfully.")
}
