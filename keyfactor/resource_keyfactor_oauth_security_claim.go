package keyfactor

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
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
				Type:                types.StringType,
				Required:            true,
				Description:         "A string containing the claim type of the OAuth security claim in Keyfactor",
				MarkdownDescription: "A string containing the claim type of the OAuth security claim in Keyfactor. For allowed possible values, please refer to the `Claim Type String` values in ClaimType table in the [Command REST API documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/SecurityClaimsPOST.htm).",
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

	state, ok := getState[OAuthSecurityClaim](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("OAuth security claim id from state: ID %d...", state.ID.Value))

	claimId := int32(state.ID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed claim ID: %d...", claimId))
	tflog.Debug(ctx, fmt.Sprintf("Claim values in state: Claim Type: %s, Claim Value: %s, Provider Authentication Scheme: %s...", state.ClaimType.Value, state.ClaimValue.Value, state.ProviderAuthenticationScheme.Value))

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
		defer httpReq.Body.Close()
		body, _ := io.ReadAll(httpReq.Body)

		response.Diagnostics.AddError(
			"Error reading security claim",
			fmt.Sprintf("Could not read OAuth security claim ID %d, unexpected error: %s. Details %s ", claimId, err.Error(), string(body)),
		)
		return
	}

	var result = mapOAuthSecurityClaim(ctx, remoteState)

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
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
	plan, ok := getPlan[OAuthSecurityClaim](ctx, &request.Plan, &response.Diagnostics)
	if !ok {
		return
	}

	// Get current state
	state, ok := getState[OAuthSecurityClaim](ctx, &request.State, &response.Diagnostics)
	if !ok {
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
	remoteState, httpReq, err := req.Execute()
	if err != nil {
		defer httpReq.Body.Close()
		body, _ := io.ReadAll(httpReq.Body)

		response.Diagnostics.AddError(
			"Error updating security claim",
			fmt.Sprintf("Could not update OAuth security claim ID %d, unexpected error: %s. Details %s ", claimId, err.Error(), string(body)),
		)
		return
	}

	var result = mapOAuthSecurityClaim(ctx, remoteState)

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
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
	state, ok := getState[OAuthSecurityClaim](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	// Get order ID from state
	claimIdValue := state.ID.Value
	claimId := int32(claimIdValue)
	tflog.SetField(ctx, "claim_id", claimId)

	tflog.Debug(ctx, fmt.Sprintf("Deleting OAuth security claim ID %d...", claimId))

	api := r.p.sdkClient.V1.SecurityClaimsApi
	req := api.NewDeleteSecurityClaimsByIdRequest(ctx, claimId)

	httpReq, err := api.DeleteSecurityClaimsByIdExecute(req)

	if err != nil {
		defer httpReq.Body.Close()
		body, _ := io.ReadAll(httpReq.Body)

		response.Diagnostics.AddError(
			"Error deleting security claim",
			fmt.Sprintf("Could not delete OAuth security claim ID %d , unexpected error: %s. Details %s ", claimId, err.Error(), string(body)),
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
	ok := checkIfProviderIsConfigured(r.p, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Info(ctx, "Create called on OAuth security claim resource")

	// Retrieve values from plan
	plan, ok := getPlan[OAuthSecurityClaim](ctx, &request.Plan, &response.Diagnostics)
	if !ok {
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
	if err != nil {
		response.Diagnostics.AddError(
			"Error parsing security claim type.",
			"Could not parse security claim value "+claimValue+", error parsing claim type: "+err.Error(),
		)
		return
	}

	req := api.NewCreateSecurityClaimsRequest(ctx).
		SecurityRoleClaimDefinitionsRoleClaimDefinitionCreationRequest(v1.SecurityRoleClaimDefinitionsRoleClaimDefinitionCreationRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   claimValue,
			Description:                  plan.Description.Value,
			ProviderAuthenticationScheme: authenticationScheme,
		})

	createResponse, httpReq, err := req.Execute()
	if err != nil {
		defer httpReq.Body.Close()
		body, _ := io.ReadAll(httpReq.Body)

		response.Diagnostics.AddError(
			"Error creating security claim",
			fmt.Sprintf("Could not create OAuth security claim %s with claim type %s , unexpected error: %s. Details %s ", claimValue, claimType, err.Error(), string(body)),
		)
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created OAuth security claim. Claim ID: %d", *createResponse.Id))

	var result = mapOAuthSecurityClaim(ctx, createResponse)

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
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

	remoteState, httpReq, err := req.Execute()
	if httpReq.StatusCode == 404 {
		response.Diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unable to find OAuth security claim '%s' on Keyfactor. Read failed.", claimIdStr),
		)
		return
	}

	if err != nil {
		defer httpReq.Body.Close()
		body, _ := io.ReadAll(httpReq.Body)

		response.Diagnostics.AddError(
			"Error importing security claim",
			fmt.Sprintf("Could not import OAuth security claim ID %d , unexpected error: %s. Details %s ", claimId, err.Error(), string(body)),
		)
		return
	}

	var result = mapOAuthSecurityClaim(ctx, remoteState)

	ok := updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Debug(ctx, "OAuth security claim state imported successfully.")
}
