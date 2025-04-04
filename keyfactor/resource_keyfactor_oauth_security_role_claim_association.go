package keyfactor

import (
	"context"
	"fmt"
	"io"

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
				Type:        types.Int64Type,
				Required:    true,
				Description: "Internal ID of the OAuth security role.",
			},
			"claim_id": {
				Type:        types.Int64Type,
				Required:    true,
				Description: "Internal ID of the OAuth security claim.",
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

	var state OAuthSecurityRoleClaimAssociation
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)

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

	var result = OAuthSecurityRoleClaimAssociation{
		ID:      types.String{Value: fmt.Sprintf("%d-%d", roleId, claimId)},
		RoleID:  types.Int64{Value: int64(roleId)},
		ClaimID: types.Int64{Value: int64(claimId)},
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role claim association resource read successfully.")
}

func (r resourceOAuthSecurityRoleClaimAssociation) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// Because role claim associations are immutable, we need to delete and recreate the resource
	tflog.Info(ctx, "Update called on OAuth security role claim association resource")

	var state OAuthSecurityRoleClaimAssociation
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	roleId := int32(state.RoleID.Value)
	claimId := int32(state.ClaimID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed old role claim association. Role ID: %d, Claim ID: %d", roleId, claimId))

	// Call Delete first
	deleteRequest := tfsdk.DeleteResourceRequest{State: request.State}
	deleteResponse := tfsdk.DeleteResourceResponse{State: response.State}
	r.Delete(ctx, deleteRequest, &deleteResponse)
	if deleteResponse.Diagnostics.HasError() {
		response.Diagnostics.Append(deleteResponse.Diagnostics...)
		return
	}

	response.State.RemoveResource(ctx)

	var plan OAuthSecurityRoleClaimAssociation
	diags = request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	roleId = int32(plan.RoleID.Value)
	claimId = int32(plan.ClaimID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed new role claim association. Role ID: %d, Claim ID: %d", roleId, claimId))

	// Call Create after deletion
	createRequest := tfsdk.CreateResourceRequest{Plan: request.Plan}
	createResponse := tfsdk.CreateResourceResponse{State: response.State}
	r.Create(ctx, createRequest, &createResponse)
	response.Diagnostics.Append(createResponse.Diagnostics...)
	if response.Diagnostics.HasError() {
		return
	}

	var result = OAuthSecurityRoleClaimAssociation{
		ID:      types.String{Value: fmt.Sprintf("%d-%d", roleId, claimId)},
		RoleID:  types.Int64{Value: int64(roleId)},
		ClaimID: types.Int64{Value: int64(claimId)},
	}

	// Update state after successful recreation
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role claim association data source updated successfully.")
}

func (r resourceOAuthSecurityRoleClaimAssociation) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on OAuth security role claim association resource")

	var state OAuthSecurityRoleClaimAssociation
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
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

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	if httpReq.StatusCode == 404 {
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

	claims := []v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{}
	for _, claim := range remoteState.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))

		if claim.Id != nil && *claim.Id == claimId {
			// Skip adding claim to claims array
			continue
		}

		provider := *claim.Provider
		claimTypeEnum, err := v2.ParseCSSCMSCoreEnumsClaimType(*claim.ClaimType.Get())

		// This shouldn't happen since the claim type is coming from the API
		// But just in case
		if err != nil {
			response.Diagnostics.AddError(
				"Error creating security identity.",
				"Could not create identity role claim association, error parsing claim type "+err.Error(),
			)
			return
		}

		temp := v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   *claim.ClaimValue.Get(),
			ProviderAuthenticationScheme: *provider.AuthenticationScheme.Get(),
			Description:                  *claim.Description.Get(),
		}
		claims = append(claims, temp)
	}

	tflog.Debug(ctx, "Data source was able to import state of OAuth security role resource from remote source using ID")

	updateReq := api.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
		Id:              int32(roleId),
		Name:            *remoteState.Name.Get(),
		Description:     *remoteState.Description.Get(),
		EmailAddress:    remoteState.EmailAddress,
		PermissionSetId: *remoteState.PermissionSetId,
		Permissions:     remoteState.Permissions,
		Claims:          claims,
	})

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d...", roleId))

	_, httpResp, err := updateReq.Execute()
	if err != nil {
		defer httpResp.Body.Close()
		body, _ := io.ReadAll(httpResp.Body)

		response.Diagnostics.AddError(
			"Error updating security role claim association.",
			fmt.Sprintf("Could not update OAuth security role assocation on role ID %d , unexpected error: %s. Details %s ", roleId, err.Error(), string(body)),
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
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	tflog.Info(ctx, "Create called on OAuth security role claim association resource")
	var plan OAuthSecurityRoleClaimAssociation
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
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

	remoteRoleState, httpReq, err := roleRequest.Execute()

	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security role error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. "+err.Error(), roleId),
		)

		return
	}

	claimsApi := r.p.sdkClient.V1.SecurityClaimsApi
	claimRequest := claimsApi.NewGetSecurityClaimsByIdRequest(ctx, claimId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim ID %d...", claimId))

	remoteClaimState, httpReq, err := claimRequest.Execute()
	tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security claim ID %d from Keyfactor. Read failed. "+err.Error(), claimId),
		)
	}

	claims := []v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{}
	for _, claim := range remoteRoleState.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))

		provider := *claim.Provider
		claimTypeEnum, err := v2.ParseCSSCMSCoreEnumsClaimType(*claim.ClaimType.Get())

		// This shouldn't happen since the claim type is coming from the API
		// But just in case
		if err != nil {
			response.Diagnostics.AddError(
				"Error creating security identity.",
				"Could not create identity role claim association, error parsing claim type "+err.Error(),
			)
			return
		}

		temp := v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   *claim.ClaimValue.Get(),
			ProviderAuthenticationScheme: *provider.AuthenticationScheme.Get(),
			Description:                  *claim.Description.Get(),
		}
		claims = append(claims, temp)
	}

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
	claims = append(claims, temp)

	tflog.Debug(ctx, "Data source was able to import state of OAuth security claim from remote source using ID")

	updateReq := roleApi.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
		Id:              int32(roleId),
		Name:            *remoteRoleState.Name.Get(),
		Description:     *remoteRoleState.Description.Get(),
		EmailAddress:    remoteRoleState.EmailAddress,
		PermissionSetId: *remoteRoleState.PermissionSetId,
		Permissions:     remoteRoleState.Permissions,
		Claims:          claims,
	})

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d...", roleId))

	_, httpResp, err := updateReq.Execute()
	if err != nil {
		defer httpResp.Body.Close()
		body, _ := io.ReadAll(httpResp.Body)

		response.Diagnostics.AddError(
			"Error creating security role claim association.",
			fmt.Sprintf("Could not create OAuth security role assocation on role ID %d , unexpected error: %s. Details %s ", roleId, err.Error(), string(body)),
		)
		return
	}

	result := OAuthSecurityRoleClaimAssociation{
		ID:      types.String{Value: fmt.Sprintf("%d-%d", roleId, claimId)},
		RoleID:  types.Int64{Value: int64(roleId)},
		ClaimID: types.Int64{Value: int64(claimId)},
	}

	tflog.Debug(ctx, "Saving OAuth security role claim association resource information into state...")

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role claim association created successfully.")
}
