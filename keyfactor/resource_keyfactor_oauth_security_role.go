package keyfactor

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	v2 "github.com/Keyfactor/keyfactor-go-client-sdk/v3/api/keyfactor/v2"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceOAuthSecurityRoleType struct{}

func (r resourceOAuthSecurityRoleType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Internal ID of the OAuth security role.",
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Description of the OAuth security role",
			},
			"description": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the description of the OAuth security role.",
			},
			"email_address": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Email address associated with the OAuth security role.",
			},
			"immutable": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Indicates whether the OAuth security role is immutable.",
			},
			"permission_set_id": {
				Type:        types.StringType,
				Required:    true,
				Description: "The ID of the permission set associated with the OAuth security role. This is used to identify the permissions associated with the role.",
			},
			"permissions": {
				Type:                types.ListType{ElemType: types.StringType},
				Required:            true,
				Description:         "A list of permissions associated with the OAuth security role. This will return a list of permissions that are associated with the OAuth security role. This is used to identify the permissions associated with the role.",
				MarkdownDescription: "A list of permissions associated with the OAuth security role. This will return a list of permissions that are associated with the OAuth security role. This is used to identify the permissions associated with the role. For more information about allowed permission values, please refer to the Keyfactor Command [Version Two Permission Model documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityRolePermissions.htm#Version2).",
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
							Required:    true,
							Description: "The description of the OAuth security claim in Keyfactor",
						},
						"claim_type": {
							Type:        types.StringType,
							Required:    true,
							Description: "The claim type of the OAuth security claim in Keyfactor",
						},
						"claim_value": {
							Type:        types.StringType,
							Required:    true,
							Description: "The claim value of the OAuth security claim in Keyfactor",
						},
						"provider_authentication_scheme": {
							Type:        types.StringType,
							Required:    true,
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
				Required:    true,
				Description: "A list of OAuth security claims associated with the OAuth security role in Keyfactor",
			},
		},
		Description: "Used to manage Keyfactor Command Security Roles using the V2 `/Security/Roles` API. This resource is compatible with Keyfactor Command versions 11+",
	}, nil
}

func (r resourceOAuthSecurityRoleType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceOAuthSecurityRole{
		p: *(p.(*provider)),
	}, nil
}

type resourceOAuthSecurityRole struct {
	p provider
}

func (r resourceOAuthSecurityRole) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	tflog.Info(ctx, "Read called on OAuth security role resource")

	var state OAuthSecurityRole
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)

	tflog.Debug(ctx, fmt.Sprintf("OAuth security claim role from state: ID %d...", state.ID.Value))

	roleId := int32(state.ID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed role ID: %d", roleId))

	tflog.SetField(ctx, "role_id", roleId)

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewGetSecurityRolesByIdRequest(ctx, roleId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security role %d...", roleId))

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
			fmt.Sprintf("Unknown error while trying to import OAuth security role '%d' on Keyfactor. Read failed. "+err.Error(), roleId),
		)

		return
	}

	var permissionValues []attr.Value
	for _, perm := range remoteState.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		permissionValues = append(permissionValues, types.String{Value: perm})
	}

	claims := []OAuthSecurityClaim{}
	for _, claim := range remoteState.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))
		provider := *claim.Provider
		temp := OAuthSecurityClaim{
			ID:                           types.Int64{Value: int64(*claim.Id)},
			Description:                  types.String{Value: *claim.Description.Get()},
			ClaimType:                    types.String{Value: *claim.ClaimType.Get()},
			ClaimValue:                   types.String{Value: *claim.ClaimValue.Get()},
			ProviderAuthenticationScheme: types.String{Value: *provider.AuthenticationScheme.Get()},
			Provider:                     mapAuthenticationProviderTypeV2(provider.Id, provider.AuthenticationScheme.Get(), provider.DisplayName.Get()),
		}
		claims = append(claims, temp)
	}

	tflog.Debug(ctx, "Data source was able to read OAuth security role resource from remote source using ID")

	var result = OAuthSecurityRole{
		ID:              types.Int64{Value: int64(*remoteState.Id)},
		Immutable:       types.Bool{Value: *remoteState.Immutable},
		EmailAddress:    getStringType(remoteState.EmailAddress.Get()),
		Description:     getStringType(remoteState.Description.Get()),
		Name:            getStringType(remoteState.Name.Get()),
		PermissionSetId: getStringType(remoteState.PermissionSetId),
		Permissions:     types.List{ElemType: types.StringType, Elems: permissionValues},
		Claims:          claims,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role resource read successfully.")
}

func (r resourceOAuthSecurityRole) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	tflog.Info(ctx, "Update called on OAuth security role resource")

	// Get plan values
	var plan OAuthSecurityRole
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state OAuthSecurityRole
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	roleName := plan.Name.Value
	roleId := int32(state.ID.Value)

	permissionArray := []string{}
	for _, permission := range plan.Permissions.Elems {
		permissionStr := strings.Trim(permission.String(), "\"") // Remove unnecessary wrapping quotes
		tflog.Debug(ctx, fmt.Sprintf("Appending permission %s to array....\n", permissionStr))
		permissionArray = append(permissionArray, permissionStr)
	}

	var claims []v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest
	for _, claim := range plan.Claims {
		claimTypeEnum, err := v2.ParseCSSCMSCoreEnumsClaimType(claim.ClaimType.Value)
		if err != nil {
			response.Diagnostics.AddError(
				"Error parsing claim type",
				fmt.Sprintf("Unable to parse claim type with name %s. Error: %s", claim.ClaimType.Value, err.Error()),
			)
			return
		}

		claims = append(claims, v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   claim.ClaimValue.Value,
			Description:                  claim.Description.Value,
			ProviderAuthenticationScheme: claim.ProviderAuthenticationScheme.Value,
		})
	}

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
		Id:              roleId,
		Name:            roleName,
		Description:     plan.Description.Value,
		EmailAddress:    *v2.NewNullableString(&plan.EmailAddress.Value),
		PermissionSetId: plan.PermissionSetId.Value,
		Permissions:     permissionArray,
		Claims:          claims,
	})

	tflog.Debug(ctx, fmt.Sprintf("Updating OAuth security role with ID: %d, name: %s;\n\tDescription: %s;\n\tEmailAddress: %s;\nt\tPermissionSetId: %s", roleId, roleName, plan.Description.Value, plan.EmailAddress.Value, plan.PermissionSetId.Value))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role..."))

	updateResponse, http, err := req.Execute()
	if err != nil {
		response.Diagnostics.AddError(
			"Error updating security role.",
			"Could not update OAuth security role "+roleName+", unexpected error: "+err.Error(),
		)
		// read body of http

		defer http.Body.Close()

		body, _ := io.ReadAll(http.Body)
		response.Diagnostics.AddError("Error updating security role.", string(body))
		return
	}

	// To be on the safe side, map the permissions returned from the API response
	var responsePermissions []attr.Value
	for _, perm := range updateResponse.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		responsePermissions = append(responsePermissions, types.String{Value: perm})
	}

	responseClaims := []OAuthSecurityClaim{}
	for _, claim := range updateResponse.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))
		provider := *claim.Provider
		temp := OAuthSecurityClaim{
			ID:                           types.Int64{Value: int64(*claim.Id)},
			Description:                  getStringType(claim.Description.Get()),
			ClaimType:                    getStringType(claim.ClaimType.Get()),
			ClaimValue:                   getStringType(claim.ClaimValue.Get()),
			ProviderAuthenticationScheme: getStringType(provider.AuthenticationScheme.Get()),
			Provider:                     mapAuthenticationProviderTypeV2(provider.Id, provider.AuthenticationScheme.Get(), provider.DisplayName.Get()),
		}
		responseClaims = append(responseClaims, temp)
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully updated OAuth security role. Role ID: %d", *updateResponse.Id))

	var result = OAuthSecurityRole{
		ID:              types.Int64{Value: int64(*updateResponse.Id)},
		Name:            getStringType(updateResponse.Name.Get()),
		Description:     getStringType(updateResponse.Description.Get()),
		EmailAddress:    getStringType(updateResponse.EmailAddress.Get()),
		PermissionSetId: getStringType(updateResponse.PermissionSetId),
		Immutable:       types.Bool{Value: *updateResponse.Immutable},
		Permissions:     types.List{ElemType: types.StringType, Elems: responsePermissions},
		Claims:          responseClaims,
	}

	tflog.Debug(ctx, "Saving OAuth security role resource information into state...")

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role data source updated successfully.")
}

func (r resourceOAuthSecurityRole) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on OAuth security role resource")
	var state OAuthSecurityRole
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	roleId := int32(state.ID.Value)
	tflog.SetField(ctx, "role_id", roleId)

	tflog.Debug(ctx, fmt.Sprintf("Deleting OAuth security role ID %d...", roleId))

	api := r.p.sdkClient.V1.SecurityRolesApi
	req := api.NewDeleteSecurityRolesByIdRequest(ctx, roleId)

	_, err := req.Execute()

	if err != nil {
		response.Diagnostics.AddError(
			"Error deleting OAuth security role.",
			"Could not delete OAuth security role "+state.Name.Value+", unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "OAuth security role deleted successfully.")

	// Remove resource from state
	response.State.RemoveResource(ctx)
}

func (r resourceOAuthSecurityRole) Create(
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

	tflog.Info(ctx, "Create called on OAuth security role resource")
	var plan OAuthSecurityRole
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "An error occurred getting the plan")
		for _, err := range response.Diagnostics.Errors() {
			tflog.Error(ctx, fmt.Sprintf("Error: %s\n===Detail: %s\n", err.Summary(), err.Detail()))
		}
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Extracted Terraform plan: %+v", plan))

	roleName := plan.Name.Value

	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, fmt.Sprintf("Creating OAuth security role with name: %s", roleName))

	permissionArray := []string{}
	for _, permission := range plan.Permissions.Elems {
		permissionStr := strings.Trim(permission.String(), "\"") // Remove unnecessary wrapping quotes
		tflog.Debug(ctx, fmt.Sprintf("Appending permission %s to array....\n", permissionStr))
		permissionArray = append(permissionArray, permissionStr)
	}

	claims := []v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{}
	for _, claim := range plan.Claims {
		claimTypeEnum, err := v2.ParseCSSCMSCoreEnumsClaimType(claim.ClaimType.Value)
		if err != nil {
			response.Diagnostics.AddError(
				"Error parsing claim type",
				fmt.Sprintf("Unable to parse claim type with name %s. Error: %s", claim.ClaimType.Value, err.Error()),
			)
			return
		}

		claims = append(claims, v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
			ClaimType:                    *claimTypeEnum,
			ClaimValue:                   claim.ClaimValue.Value,
			Description:                  claim.Description.Value,
			ProviderAuthenticationScheme: claim.ProviderAuthenticationScheme.Value,
		})
	}

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewCreateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleCreationRequest(v2.SecuritySecurityRolesSecurityRoleCreationRequest{
		Name:            roleName,
		Description:     plan.Description.Value,
		EmailAddress:    *v2.NewNullableString(&plan.EmailAddress.Value),
		PermissionSetId: plan.PermissionSetId.Value,
		Permissions:     permissionArray,
		Claims:          claims,
	})

	tflog.Debug(ctx, fmt.Sprintf("Creating OAuth security role with name: %s;\n\tDescription: %s;\n\tEmailAddress: %s;\nt\tPermissionSetId: %s", roleName, plan.Description.Value, plan.EmailAddress.Value, plan.PermissionSetId.Value))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to create OAuth security role..."))

	createResponse, http, err := req.Execute()
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating security role.",
			"Could not create OAuth security role "+roleName+", unexpected error: "+err.Error(),
		)
		// read body of http

		defer http.Body.Close()

		body, _ := io.ReadAll(http.Body)
		response.Diagnostics.AddError("Error creating security role.", string(body))
		return
	}

	// To be on the safe side, map the permissions returned from the API response
	var responsePermissions []attr.Value
	for _, perm := range createResponse.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		responsePermissions = append(responsePermissions, types.String{Value: perm})
	}

	responseClaims := []OAuthSecurityClaim{}
	for _, claim := range createResponse.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))
		provider := *claim.Provider
		temp := OAuthSecurityClaim{
			ID:                           types.Int64{Value: int64(*claim.Id)},
			Description:                  getStringType(claim.Description.Get()),
			ClaimType:                    getStringType(claim.ClaimType.Get()),
			ClaimValue:                   getStringType(claim.ClaimValue.Get()),
			ProviderAuthenticationScheme: getStringType(provider.AuthenticationScheme.Get()),
			Provider:                     mapAuthenticationProviderTypeV2(provider.Id, provider.AuthenticationScheme.Get(), provider.DisplayName.Get()),
		}
		responseClaims = append(responseClaims, temp)
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created OAuth security role. Role ID: %d", *createResponse.Id))

	var result = OAuthSecurityRole{
		ID:              types.Int64{Value: int64(*createResponse.Id)},
		Name:            getStringType(createResponse.Name.Get()),
		Description:     getStringType(createResponse.Description.Get()),
		EmailAddress:    getStringType(createResponse.EmailAddress.Get()),
		PermissionSetId: getStringType(createResponse.PermissionSetId),
		Immutable:       types.Bool{Value: *createResponse.Immutable},
		Permissions:     types.List{ElemType: types.StringType, Elems: responsePermissions},
		Claims:          responseClaims,
	}

	tflog.Debug(ctx, "Saving OAuth security role resource information into state...")

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role data source created successfully.")
}

func (r resourceOAuthSecurityRole) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on OAuth security role resource")

	requestId := request.ID

	tflog.Debug(ctx, fmt.Sprintf("OAuth security claim role ID requested: %s...", requestId))

	roleId, err := strconv.Atoi(requestId)

	tflog.Debug(ctx, fmt.Sprintf("Parsed role ID: %d", roleId))

	tflog.SetField(ctx, "role_id", roleId)

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewGetSecurityRolesByIdRequest(ctx, int32(roleId))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security role %d...", roleId))

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
			fmt.Sprintf("Unknown error while trying to import OAuth security role '%d' on Keyfactor. Read failed. "+err.Error(), roleId),
		)

		return
	}

	var permissionValues []attr.Value
	for _, perm := range remoteState.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		permissionValues = append(permissionValues, types.String{Value: perm})
	}

	claims := []OAuthSecurityClaim{}
	for _, claim := range remoteState.Claims {
		tflog.Debug(ctx, fmt.Sprintf("Claim ID: %d", *claim.Id))
		provider := *claim.Provider
		temp := OAuthSecurityClaim{
			ID:                           types.Int64{Value: int64(*claim.Id)},
			Description:                  types.String{Value: *claim.Description.Get()},
			ClaimType:                    types.String{Value: *claim.ClaimType.Get()},
			ClaimValue:                   types.String{Value: *claim.ClaimValue.Get()},
			ProviderAuthenticationScheme: types.String{Value: *provider.AuthenticationScheme.Get()},
			Provider:                     mapAuthenticationProviderTypeV2(provider.Id, provider.AuthenticationScheme.Get(), provider.DisplayName.Get()),
		}
		claims = append(claims, temp)
	}

	tflog.Debug(ctx, "Data source was able to import state of OAuth security role resource from remote source using ID")

	var result = OAuthSecurityRole{
		ID:              types.Int64{Value: int64(*remoteState.Id)},
		Description:     types.String{Value: *remoteState.Description.Get()},
		Name:            types.String{Value: *remoteState.Name.Get()},
		PermissionSetId: types.String{Value: *remoteState.PermissionSetId},
		Permissions:     types.List{ElemType: types.StringType, Elems: permissionValues},
		Claims:          claims,
	}

	diags := response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security role resource imported successfully.")
}
