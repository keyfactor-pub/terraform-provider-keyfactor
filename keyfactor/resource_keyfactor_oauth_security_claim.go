package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v3/api/keyfactor/v1"
)

type resourceOAuthSecurityClaimType struct{}

func (r resourceOAuthSecurityClaimType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Internal ID of the role.",
			},
			"description": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the description of the OAuth security claim in Keyfactor",
			},
			"claim_type": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the claim type of the OAuth security claim in Keyfactor",
			},
			"claim_value": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the claim value of the OAuth security claim in Keyfactor",
			},
			"provider_authentication_scheme": {
				Type:        types.StringType,
				Required:    true,
				Description: "The identity provider associated with the OAuth security claim. Used only for resource creation. Not returned by the API.",
			},
			// "provider": {
			// 	Attributes: tfsdk.SingleNestedAttributes(
			// 		map[string]tfsdk.Attribute{
			// 			"id": {
			// 				Type:        types.StringType,
			// 				Description: "Internal ID of the authentication provider",
			// 				Computed:    true,
			// 			},
			// 			"authentication_scheme": {
			// 				Type:        types.StringType,
			// 				Description: "The authentication scheme used by the provider",
			// 				Computed:    true,
			// 			},
			// 			"display_name": {
			// 				Type:        types.StringType,
			// 				Description: "The display name of the provider",
			// 				Computed:    true,
			// 			},
			// 		},
			// 	),
			// 	Computed:    true,
			// 	Description: "An object containing the provider of the OAuth security claim in Keyfactor",
			// },
		},
		Description: "An OAuth security claim in Keyfactor Command",
	}, nil
}

// New resource instance
func (r resourceOAuthSecurityClaimType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceOAuthSecurityClaim{
		p: *(p.(*provider)),
	}, nil
}

type resourceOAuthSecurityClaim struct {
	p provider
}

func (r resourceOAuthSecurityClaim) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	tflog.Info(ctx, "Read called on OAuth security claim resource")
	// NOOP

	var state OAuthSecurityClaim
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)

	tflog.Debug(ctx, fmt.Sprintf("OAuth security claim id from state: %d...", state.ID.Value))

	claimId := int32(state.ID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed claim ID: %d...", claimId))

	tflog.SetField(ctx, "claim_id", claimId)

	api := r.p.sdkClient.V1.SecurityClaimsApi
	req := api.GetSecurityClaimsById(ctx, int32(claimId))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim %d...", claimId))

	remoteState, httpReq, err := api.GetSecurityClaimsByIdExecute(req)

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	if httpReq.StatusCode == 404 {
		tflog.Info(ctx, fmt.Sprintf("OAuth Security Claim %d not found in remote system. Removing from state", claimId))
		response.State.RemoveResource(ctx)
		return
	}

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security claim '%d' on Keyfactor. Read failed. "+err.Error(), claimId),
		)

		return
	}

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*remoteState.Id)},
		Description:                  types.String{Value: *remoteState.Description.Get()},
		ClaimType:                    types.String{Value: *remoteState.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *remoteState.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *remoteState.Provider.AuthenticationScheme.Get()},
		// Provider: &OAuthSecurityClaimAuthenticationProvider{
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceOAuthSecurityClaim) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// // Get plan values
	// var plan OAuthSecurityClaim
	// diags := request.Plan.Get(ctx, &plan)
	// response.Diagnostics.Append(diags...)
	// if response.Diagnostics.HasError() {
	// 	return
	// }

	tflog.Info(ctx, "Update called on OAuth security claim resource")

	// // Get current state
	// var state OAuthSecurityClaim
	// diags = request.State.Get(ctx, &state)
	// response.Diagnostics.Append(diags...)
	// if response.Diagnostics.HasError() {
	// 	return
	// }

	// roleId := state.ID.Value
	// tflog.SetField(ctx, "id", roleId)

	// // Generate API request body from plan

	// var permissions []string
	// plan.Permissions.ElementsAs(ctx, &permissions, false)
	// //Update role identities
	// updateArg := &api.UpdateSecurityRoleArg{
	// 	Id: int(roleId),
	// 	CreateSecurityRoleArg: api.CreateSecurityRoleArg{
	// 		Name:        plan.Name.Value,
	// 		Description: plan.Description.Value,
	// 		Permissions: &permissions,
	// 	},
	// }

	// remoteState, err := r.p.client.UpdateSecurityRole(updateArg)
	// if err != nil {
	// 	response.Diagnostics.AddError(
	// 		"Identity role update error.",
	// 		fmt.Sprintf("Error updating identity role '%s': "+err.Error(), plan.Name.Value),
	// 	)
	// 	return
	// }

	// var permissionValues []attr.Value
	// sort.Strings(*remoteState.Permissions)
	// for _, perm := range *remoteState.Permissions {
	// 	tflog.Info(ctx, "Permission: "+perm)
	// 	permissionValues = append(
	// 		permissionValues, types.String{
	// 			Value: perm,
	// 		},
	// 	)
	// }

	// var result = SecurityRole{
	// 	ID:          types.Int64{Value: int64(state.ID.Value)},
	// 	Name:        types.String{Value: remoteState.Name},
	// 	Description: types.String{Value: remoteState.Description},
	// 	Permissions: types.List{ElemType: types.StringType, Elems: permissionValues},
	// }

	// // Set state
	// diags = response.State.Set(ctx, result)
	// response.Diagnostics.Append(diags...)
	// if response.Diagnostics.HasError() {
	// 	return
	// }
}

func (r resourceOAuthSecurityClaim) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on OAuth security claim resource")
	// var state SecurityRole
	// diags := request.State.Get(ctx, &state)
	// kfClient := r.p.client

	// response.Diagnostics.Append(diags...)
	// if response.Diagnostics.HasError() {
	// 	return
	// }

	// // Get order ID from state
	// identityId := state.ID.Value

	// // Delete order by calling API
	// err := kfClient.DeleteSecurityRole(int(identityId))
	// if err != nil {
	// 	response.Diagnostics.AddError(
	// 		ERR_SUMMARY_IDENTITY_DELETE,
	// 		"Could not delete "+state.Name.Value+" from Keyfactor Command: "+err.Error(),
	// 	)
	// 	return
	// }

	// // Remove resource from state
	// response.State.RemoveResource(ctx)

}

func (r resourceOAuthSecurityClaim) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	tflog.Info(ctx, "Create called on OAuth security claim resource")

	// Retrieve values from plan
	var plan OAuthSecurityClaim
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "An error occurred getting the plan")
		for _, err := range response.Diagnostics.Errors() {
			tflog.Error(ctx, fmt.Sprintf("Error: %s\n===Detail: %s\n", err.Summary(), err.Detail()))
		}
		return
	}

	// Generate API request body from plan
	claimType := plan.ClaimType.Value
	claimValue := plan.ClaimValue.Value
	authenticationScheme := plan.ProviderAuthenticationScheme.Value

	tflog.Debug(ctx, fmt.Sprintf("OAuth security claim fields retrieved:\n\tClaimType: %s\n\tClaimValue: %s\n\tAuthentication Scheme: %s\n", claimType, claimValue, authenticationScheme))

	ctx = tflog.SetField(ctx, "claim_value", claimValue)
	tflog.Debug(ctx, "Creating Keyfactor OAuth security claim resource")

	api := r.p.sdkClient.V1.SecurityClaimsApi
	claimTypeEnum, err := v1.ParseCSSCMSCoreEnumsClaimType(claimType)
	req := api.CreateSecurityClaims(ctx).
		SecurityRoleClaimDefinitionsRoleClaimDefinitionCreationRequest(v1.SecurityRoleClaimDefinitionsRoleClaimDefinitionCreationRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   claimValue,
			Description:                  plan.Description.Value,
			ProviderAuthenticationScheme: authenticationScheme,
		})

	createResponse, _, err := api.CreateSecurityClaimsExecute(req)
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating security identity.",
			"Could not create identity "+claimValue+", unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created OAuth security claim. Claim ID: %d", *createResponse.Id))

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*createResponse.Id)},
		Description:                  types.String{Value: *createResponse.Description.Get()},
		ClaimType:                    types.String{Value: *createResponse.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *createResponse.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *createResponse.Provider.AuthenticationScheme.Get()},
		// Provider: &OAuthSecurityClaimAuthenticationProvider{
		// 	ID:                   types.String{Value: *createResponse.Provider.Id},
		// 	AuthenticationScheme: types.String{Value: *createResponse.Provider.AuthenticationScheme.Get()},
		// 	DisplayName:          types.String{Value: *createResponse.Provider.DisplayName.Get()},
		// },
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceOAuthSecurityClaim) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on OAuth security claim resource")
	claimIdStr := request.ID
	claimId, err := strconv.Atoi(claimIdStr)

	if err != nil {
		response.Diagnostics.AddError(
			"Invalid claim ID",
			fmt.Sprintf("Invalid claim ID '%v'. Must be an integer.", claimIdStr),
		)
		return
	}

	tflog.SetField(ctx, "claim_id", claimIdStr)

	api := r.p.sdkClient.V1.SecurityClaimsApi
	req := api.GetSecurityClaimsById(ctx, int32(claimId))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim %s...", claimIdStr))

	remoteState, _, err := api.GetSecurityClaimsByIdExecute(req)
	if remoteState == nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unable to find OAuth security claim '%s' on Keyfactor. Read failed.", claimIdStr),
		)
		return
	}

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security claim '%s' on Keyfactor. Read failed. "+err.Error(), claimIdStr),
		)
		return
	}

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*remoteState.Id)},
		Description:                  types.String{Value: *remoteState.Description.Get()},
		ClaimType:                    types.String{Value: *remoteState.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *remoteState.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *remoteState.Provider.AuthenticationScheme.Get()},
		// Provider: &OAuthSecurityClaimAuthenticationProvider{
	}

	diags := response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	if response.Diagnostics.HasError() {
		return
	}
}
