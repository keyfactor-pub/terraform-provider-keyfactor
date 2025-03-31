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
			"provider": {
				Type: types.ObjectType{
					AttrTypes: OAuthSecurityClaimAuthenticationProviderType,
				},
				Computed:    true,
				Description: "An object containing the provider of the OAuth security claim in Keyfactor",
			},
		},
		Description: "Used to manage Keyfactor Command Security Claims using the V1 `/Security/Claims` API. This resource is compatible with Keyfactor Command versions 11+",
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

	var state OAuthSecurityClaim
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)

	tflog.Debug(ctx, fmt.Sprintf("OAuth security claim id from state: ID %d...", state.ID.Value))

	claimId := int32(state.ID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed claim ID: %d...", claimId))

	tflog.SetField(ctx, "claim_id", claimId)

	api := r.p.sdkClient.V1.SecurityClaimsApi
	req := api.NewGetSecurityClaimsByIdRequest(ctx, claimId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim %d...", claimId))

	remoteState, httpReq, err := req.Execute()

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

	provider := *remoteState.Provider

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*remoteState.Id)},
		Description:                  types.String{Value: *remoteState.Description.Get()},
		ClaimType:                    types.String{Value: *remoteState.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *remoteState.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *remoteState.Provider.AuthenticationScheme.Get()},
		Provider:                     mapAuthenticationProviderType(*provider.Id, *provider.AuthenticationScheme.Get(), *provider.DisplayName.Get()),
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security claim read successfully.")
}

func (r resourceOAuthSecurityClaim) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	tflog.Info(ctx, "Update called on OAuth security claim resource")

	// Get plan values
	var plan OAuthSecurityClaim
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state OAuthSecurityClaim
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("ClaimType: %s, ClaimValue: %s, ProviderAuthenticationScheme: %s, Claim ID: %d",
		plan.ClaimType.Value,
		plan.ClaimValue.Value,
		plan.ProviderAuthenticationScheme.Value,
		state.ID.Value))

	claimIdValue := state.ID.Value
	claimId := int32(claimIdValue)
	tflog.SetField(ctx, "claim_id", claimId)

	// Generate API request
	api := r.p.sdkClient.V1.SecurityClaimsApi
	req := api.NewUpdateSecurityClaimsRequest(ctx).SecurityRoleClaimDefinitionsRoleClaimDefinitionUpdateRequest(v1.SecurityRoleClaimDefinitionsRoleClaimDefinitionUpdateRequest{
		Id:          claimId,
		Description: plan.Description.Value,
	})

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to update OAuth security claim id %d...", claimId))

	// Execute API request
	remoteState, _, err := req.Execute()
	if err != nil {
		response.Diagnostics.AddError(
			"Error updating security identity.",
			"Could not update identity "+plan.ClaimValue.Value+", unexpected error: "+err.Error(),
		)
		return
	}

	provider := *remoteState.Provider

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*remoteState.Id)},
		Description:                  types.String{Value: *remoteState.Description.Get()},
		ClaimType:                    types.String{Value: *remoteState.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *remoteState.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *provider.AuthenticationScheme.Get()},
		Provider:                     mapAuthenticationProviderType(*provider.Id, *provider.AuthenticationScheme.Get(), *provider.DisplayName.Get()),
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security claim updated successfully.")
}

func (r resourceOAuthSecurityClaim) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on OAuth security claim resource")
	var state OAuthSecurityClaim
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get order ID from state
	claimIdValue := state.ID.Value
	claimId := int32(claimIdValue)
	tflog.SetField(ctx, "claim_id", claimId)

	tflog.Debug(ctx, fmt.Sprintf("Deleting OAuth security claim ID %d...", claimId))

	api := r.p.sdkClient.V1.SecurityClaimsApi
	req := api.NewDeleteSecurityClaimsByIdRequest(ctx, claimId)

	_, err := api.DeleteSecurityClaimsByIdExecute(req)

	if err != nil {
		response.Diagnostics.AddError(
			"Error deleting OAuth security claim.",
			"Could not delete OAuth security claim "+state.ClaimValue.Value+", unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "OAuth security claim deleted successfully.")

	// Remove resource from state
	response.State.RemoveResource(ctx)

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
	req := api.NewCreateSecurityClaimsRequest(ctx).
		SecurityRoleClaimDefinitionsRoleClaimDefinitionCreationRequest(v1.SecurityRoleClaimDefinitionsRoleClaimDefinitionCreationRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   claimValue,
			Description:                  plan.Description.Value,
			ProviderAuthenticationScheme: authenticationScheme,
		})

	createResponse, _, err := req.Execute()
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating security identity.",
			"Could not create identity "+claimValue+", unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created OAuth security claim. Claim ID: %d", *createResponse.Id))

	provider := *createResponse.Provider

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*createResponse.Id)},
		Description:                  types.String{Value: *createResponse.Description.Get()},
		ClaimType:                    types.String{Value: *createResponse.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *createResponse.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *createResponse.Provider.AuthenticationScheme.Get()},
		Provider:                     mapAuthenticationProviderType(*provider.Id, *provider.AuthenticationScheme.Get(), *provider.DisplayName.Get()),
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security claim created successfully.")
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
	req := api.NewGetSecurityClaimsByIdRequest(ctx, int32(claimId))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim ID %d...", claimId))

	remoteState, _, err := req.Execute()
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

	provider := *remoteState.Provider

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*remoteState.Id)},
		Description:                  types.String{Value: *remoteState.Description.Get()},
		ClaimType:                    types.String{Value: *remoteState.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *remoteState.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *remoteState.Provider.AuthenticationScheme.Get()},
		Provider:                     mapAuthenticationProviderType(*provider.Id, *provider.AuthenticationScheme.Get(), *provider.DisplayName.Get()),
	}

	diags := response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security claim state imported successfully.")
}
