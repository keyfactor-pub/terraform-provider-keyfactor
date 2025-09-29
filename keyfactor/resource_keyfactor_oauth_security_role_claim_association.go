package keyfactor

import (
	"context"
	"fmt"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceOAuthSecurityRoleClaimAssociationType struct{}

func (r resourceOAuthSecurityRoleClaimAssociationType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Internal ID of the OAuth security role claim association.",
			},
			"role_id": {
				Type:          types.Int64Type,
				Required:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Internal ID of the OAuth security role. Changing this value forces a new resource.",
			},
			"claim_id": {
				Type:          types.Int64Type,
				Required:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Internal ID of the OAuth security claim. Changing this value forces a new resource.",
			},
		},
		Description: "Used to associate an existing OAuth security claim with an existing OAuth security claim resource using the V1 `/Security/Claims/` and V2 `/Security/Roles` APIs. This resource is compatible with Keyfactor Command versions 11+",
	}, nil
}

func (r resourceOAuthSecurityRoleClaimAssociationType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceOAuthSecurityRoleClaimAssociation{
		p: *(p.(*provider)),
	}, nil
}

type resourceOAuthSecurityRoleClaimAssociation struct {
	p provider
}

func (r resourceOAuthSecurityRoleClaimAssociation) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	tflog.Info(ctx, "Read called on OAuth security role claim association resource")

	state, ok := getState[OAuthSecurityRoleClaimAssociation](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("OAuth security role claim association from state: Role ID %d, Claim ID: %d...", state.RoleID.Value, state.ClaimID.Value))

	roleId := int32(state.RoleID.Value)
	claimId := int32(state.ClaimID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed role ID: %d, Parsed claim ID: %d", roleId, claimId))

	tflog.SetField(ctx, "role_id", roleId)
	tflog.SetField(ctx, "claim_id", claimId)

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewGetSecurityRolesByIdRequest(ctx, roleId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security role ID %d...", roleId))

	remoteState, httpReq, err := req.Execute()

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	if httpReq.StatusCode == 404 {
		tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing role claim association from state", roleId))
		response.State.RemoveResource(ctx)
		return
	}

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security role error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. "+err.Error(), roleId),
		)

		return
	}

	// See if the claim is associated with the role
	remoteClaimFound := false
	for _, claim := range remoteState.Claims {
		if claim.Id != nil && *claim.Id == claimId {
			remoteClaimFound = true
			break
		}
	}

	if !remoteClaimFound {
		tflog.Info(ctx, fmt.Sprintf("OAuth Security Claim %d not found on security role ID %d. Removing role claim association from state", claimId, roleId))
		response.State.RemoveResource(ctx)
		return
	}

	tflog.Debug(ctx, "Data source was able to read OAuth security role claim association from resource")

	result := mapOAuthSecurityRoleClaimAssociation(ctx, roleId, claimId)

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Debug(ctx, "OAuth security role claim association resource read successfully.")
}

func (r resourceOAuthSecurityRoleClaimAssociation) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// Any updates to role claim association results in a delete & create.
	// NOOP
}

func (r resourceOAuthSecurityRoleClaimAssociation) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on OAuth security role claim association resource")

	state, ok := getState[OAuthSecurityRoleClaimAssociation](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	roleId := int32(state.RoleID.Value)
	claimId := int32(state.ClaimID.Value)

	tflog.SetField(ctx, "role_id", roleId)
	tflog.SetField(ctx, "claim_id", claimId)

	tflog.Debug(ctx, fmt.Sprintf("Deleting OAuth security role claim association. Role ID %d, Claim ID %d...", roleId, claimId))

	api := r.p.sdkClient.V2.SecurityRolesApi

	numberOfAttempts := 0

	for {
		if numberOfAttempts >= maxRoleUpdateAttempts {
			response.Diagnostics.AddError(
				"Error deleting security role claim association.",
				fmt.Sprintf("Could not delete OAuth security role assocation on role ID %d to remove claim ID %d after %d attempts. Please verify the claim and role exist and try again.", roleId, claimId, maxRoleUpdateAttempts),
			)
			return
		}

		numberOfAttempts++

		tflog.Debug(ctx, fmt.Sprintf("Attempt %d to remove OAuth security role claim association on role ID %d to remove claim ID %d...", numberOfAttempts, roleId, claimId))

		remoteState, httpResp, err := getSecurityRole(ctx, api, roleId, response.Diagnostics)

		// If security role is no longer found, remove role claim association from Terraform state
		if httpResp.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
			response.State.RemoveResource(ctx)
			return
		}

		if err != nil {
			response.Diagnostics.AddError(
				"Unknown OAuth security role error.",
				fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. "+err.Error(), roleId),
			)

			return
		}

		updateReq, err := buildSecurityRoleUpdateRequest(ctx, api, remoteState, nil, &response.Diagnostics)

		tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d to remove claim ID %d...", roleId, claimId))

		_, httpResp, err = updateReq.Execute()

		// If security role is no longer found, remove role claim association from Terraform state
		if httpResp.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
			response.State.RemoveResource(ctx)
			return
		}

		if err == nil {
			break
		}

		handleRoleUpdateError(ctx, httpResp, err, roleId)
	}

	tflog.Info(ctx, "OAuth security role claim associated deleted successfully.")

	// Remove resource from state
	response.State.RemoveResource(ctx)
	return
}

func (r resourceOAuthSecurityRoleClaimAssociation) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	ok := checkIfProviderIsConfigured(r.p, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Info(ctx, "Create called on OAuth security role claim association resource")
	plan, ok := getPlan[OAuthSecurityRoleClaimAssociation](ctx, &request.Plan, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Extracted Terraform plan: %+v", plan))

	roleId := int32(plan.RoleID.Value)
	claimId := int32(plan.ClaimID.Value)

	tflog.SetField(ctx, "role_id", roleId)
	tflog.SetField(ctx, "claim_id", claimId)
	tflog.Debug(ctx, fmt.Sprintf("Creating OAuth security role claim association. Role ID: %d, Claim ID: %d", roleId, claimId))

	roleApi := r.p.sdkClient.V2.SecurityRolesApi
	claimsApi := r.p.sdkClient.V1.SecurityClaimsApi

	remoteClaimState, err := getSecurityClaim(ctx, claimsApi, claimId, response.Diagnostics)

	if err != nil {
		return
	}

	numberOfAttempts := 0

	for {
		if numberOfAttempts >= maxRoleUpdateAttempts {
			response.Diagnostics.AddError(
				"Error creating security role claim association.",
				fmt.Sprintf("Could not create OAuth security role assocation on role ID %d to add claim ID %d after %d attempts. Please verify the claim and role exist and try again.", roleId, claimId, maxRoleUpdateAttempts),
			)
			return
		}

		numberOfAttempts++

		tflog.Debug(ctx, fmt.Sprintf("Attempt %d to create OAuth security role claim association on role ID %d to add claim ID %d...", numberOfAttempts, roleId, claimId))

		remoteRoleState, httpResp, err := getSecurityRole(ctx, roleApi, roleId, response.Diagnostics)

		if err != nil {
			response.Diagnostics.AddError(
				"Unknown OAuth security role error.",
				fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. "+err.Error(), roleId),
			)

			return
		}

		updateReq, err := buildSecurityRoleUpdateRequest(ctx, roleApi, remoteRoleState, remoteClaimState, &response.Diagnostics)

		tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d to add security claim id %d...", roleId, claimId))

		_, httpResp, err = updateReq.Execute()

		if err == nil {
			tflog.Debug(ctx, fmt.Sprintf("Successfully updated OAuth security role ID %d to add security claim id %d...", roleId, claimId))
			break
		}

		handleRoleUpdateError(ctx, httpResp, err, roleId)
	}

	result := mapOAuthSecurityRoleClaimAssociation(ctx, roleId, claimId)

	tflog.Debug(ctx, "Saving OAuth security role claim association resource information into state...")

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Info(ctx, "OAuth security role claim association created successfully.")
}

func getSecurityClaim(ctx context.Context, claimsApi *v1.SecurityClaimsApiService, claimId int32, diagnostics diag.Diagnostics) (*v1.SecurityRoleClaimDefinitionsRoleClaimDefinitionResponse, error) {
	claimRequest := claimsApi.NewGetSecurityClaimsByIdRequest(ctx, claimId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim ID %d...", claimId))

	remoteClaimState, httpReq, err := claimRequest.Execute()
	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	if err != nil {
		diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security claim ID %d from Keyfactor. Read failed. "+err.Error(), claimId),
		)
	}

	return remoteClaimState, err
}
