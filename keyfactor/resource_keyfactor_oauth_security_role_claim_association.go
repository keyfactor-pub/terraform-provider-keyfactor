package keyfactor

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	v2 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v2"
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

	if err != nil {
		if httpReq != nil && httpReq.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing role claim association from state", roleId))
			response.State.RemoveResource(ctx)
			return
		}

		response.Diagnostics.AddError(
			"Unknown OAuth security role error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. "+err.Error(), roleId),
		)

		return
	}

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

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
	req := api.NewGetSecurityRolesByIdRequest(ctx, int32(roleId))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security role ID %d...", roleId))

	remoteState, httpReq, err := req.Execute()

	if err != nil {
		if httpReq != nil && httpReq.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
			response.State.RemoveResource(ctx)
			return
		}

		response.Diagnostics.AddError(
			"Unknown OAuth security role error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. "+err.Error(), roleId),
		)

		return
	}

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	updatedClaims, ok := mapOAuthSecurityClaimsFromRole(ctx, &response.Diagnostics, remoteState, &claimId)
	if !ok {
		return
	}
	claims := *updatedClaims

	tflog.Debug(ctx, "Data source was able to import state of OAuth security role resource from remote source using ID")

	updateReq := api.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
		Id:              int32(roleId),
		Name:            derefOrEmpty(remoteState.Name.Get()),
		Description:     derefOrEmpty(remoteState.Description.Get()),
		EmailAddress:    remoteState.EmailAddress,
		PermissionSetId: derefOrEmpty(remoteState.PermissionSetId),
		Permissions:     remoteState.Permissions,
		Claims:          claims,
	})

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d to remove claim ID %d...", roleId, claimId))

	_, httpResp, err := updateReq.Execute()

	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
			response.State.RemoveResource(ctx)
			return
		}

		var body []byte
		if httpResp != nil {
			defer httpResp.Body.Close()
			body, _ = io.ReadAll(httpResp.Body)
		}

		response.Diagnostics.AddError(
			"Error updating security role claim association.",
			fmt.Sprintf("Could not update OAuth security role assocation on role ID %d to delete claim ID %d, unexpected error: %s. Details %s ", roleId, claimId, err.Error(), string(body)),
		)
		return
	}

	tflog.Debug(ctx, "OAuth security role claim associated deleted successfully.")

	// Remove resource from state
	response.State.RemoveResource(ctx)
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
	roleRequest := roleApi.NewGetSecurityRolesByIdRequest(ctx, int32(roleId))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security role ID %d...", roleId))

	remoteRoleState, httpResp, err := roleRequest.Execute()

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security role error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. "+err.Error(), roleId),
		)

		return
	}

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpResp.StatusCode))

	claimsApi := r.p.sdkClient.V1.SecurityClaimsApi
	claimRequest := claimsApi.NewGetSecurityClaimsByIdRequest(ctx, claimId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim ID %d...", claimId))

	remoteClaimState, httpReq, err := claimRequest.Execute()

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security claim ID %d from Keyfactor. Read failed. "+err.Error(), claimId),
		)

		return
	}

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	existingClaims, ok := mapOAuthSecurityClaimsFromRole(ctx, &response.Diagnostics, remoteRoleState, nil)
	if !ok {
		return
	}
	claims := *existingClaims

	provider := *remoteClaimState.Provider
	claimTypeEnum, err := v2.ParseCSSCMSCoreEnumsClaimType(*remoteClaimState.ClaimType.Get())

	if err != nil {
		response.Diagnostics.AddError(
			"Error creating security identity.",
			"Could not create identity role claim association, error parsing claim type "+err.Error(),
		)
		return
	}

	// Add remote claim to request
	temp := v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
		ClaimType:                    *claimTypeEnum,
		ClaimValue:                   *remoteClaimState.ClaimValue.Get(),
		ProviderAuthenticationScheme: *provider.AuthenticationScheme.Get(),
		Description:                  *remoteClaimState.Description.Get(),
	}

	updatedClaims := addOAuthSecurityClaimToRole(ctx, claims, temp)

	tflog.Debug(ctx, "Data source was able to import state of OAuth security claim from remote source using ID")

	updateReq := roleApi.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
		Id:              int32(roleId),
		Name:            derefOrEmpty(remoteRoleState.Name.Get()),
		Description:     derefOrEmpty(remoteRoleState.Description.Get()),
		EmailAddress:    remoteRoleState.EmailAddress,
		PermissionSetId: derefOrEmpty(remoteRoleState.PermissionSetId),
		Permissions:     remoteRoleState.Permissions,
		Claims:          updatedClaims,
	})

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d to add security claim id %d...", roleId, claimId))

	_, httpResp, err = updateReq.Execute()
	if err != nil {
		var body []byte
		if httpResp != nil {
			defer httpResp.Body.Close()
			body, _ = io.ReadAll(httpResp.Body)
		}

		response.Diagnostics.AddError(
			"Error creating security role claim association.",
			fmt.Sprintf("Could not create OAuth security role assocation on role ID %d to add claim ID %d, unexpected error: %s. Details %s ", roleId, claimId, err.Error(), string(body)),
		)
		return
	}

	result := mapOAuthSecurityRoleClaimAssociation(ctx, roleId, claimId)

	tflog.Debug(ctx, "Saving OAuth security role claim association resource information into state...")

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Debug(ctx, "OAuth security role claim association created successfully.")
}

// ImportState imports a role-claim association by its composite ID "<roleId>/<claimId>".
func (r resourceOAuthSecurityRoleClaimAssociation) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on OAuth security role claim association resource")

	parts := strings.SplitN(request.ID, "/", 2)
	if len(parts) != 2 {
		response.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected import ID in format '<roleId>/<claimId>', got %q.", request.ID),
		)
		return
	}

	roleId64, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid role ID",
			fmt.Sprintf("Role ID %q is not a valid integer: %s", parts[0], err.Error()),
		)
		return
	}

	claimId64, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid claim ID",
			fmt.Sprintf("Claim ID %q is not a valid integer: %s", parts[1], err.Error()),
		)
		return
	}

	roleId := int32(roleId64)
	claimId := int32(claimId64)

	tflog.SetField(ctx, "role_id", roleId)
	tflog.SetField(ctx, "claim_id", claimId)

	// Verify the role exists and the claim is associated with it.
	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewGetSecurityRolesByIdRequest(ctx, roleId)
	remoteState, httpResp, err := req.Execute()
	if httpResp != nil && httpResp.StatusCode == 404 {
		response.Diagnostics.AddError(
			"Role not found",
			fmt.Sprintf("OAuth security role ID %d not found in Keyfactor Command.", roleId),
		)
		return
	}
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading role",
			fmt.Sprintf("Could not read OAuth security role ID %d: %s", roleId, err.Error()),
		)
		return
	}

	claimFound := false
	for _, claim := range remoteState.Claims {
		if claim.Id != nil && *claim.Id == claimId {
			claimFound = true
			break
		}
	}
	if !claimFound {
		response.Diagnostics.AddError(
			"Claim association not found",
			fmt.Sprintf("Claim ID %d is not associated with role ID %d in Keyfactor Command.", claimId, roleId),
		)
		return
	}

	result := mapOAuthSecurityRoleClaimAssociation(ctx, roleId, claimId)
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
}
