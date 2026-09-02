package keyfactor

import (
	"context"
	"fmt"
	"io"
	"sort"

	v2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
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
				Type:          types.Int64Type,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Internal ID of the OAuth security role.",
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
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Email address associated with the OAuth security role.",
			},
			"immutable": {
				Type:          types.BoolType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Indicates whether the OAuth security role is immutable.",
			},
			"permission_set_id": {
				Type:        types.StringType,
				Required:    true,
				Description: "The ID of the permission set associated with the OAuth security role. This is used to identify the permissions associated with the role.",
			},
			"permissions": {
				Type:                types.SetType{ElemType: types.StringType},
				Required:            true,
				Description:         "A list of permissions associated with the OAuth security role. This will return a list of permissions that are associated with the OAuth security role. This is used to identify the permissions associated with the role.",
				MarkdownDescription: "A list of permissions associated with the OAuth security role. This will return a list of permissions that are associated with the OAuth security role. This is used to identify the permissions associated with the role. For more information about allowed permission values, please refer to the Keyfactor Command [Version Two Permission Model documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityRolePermissions.htm#Version2).",
			},
		},
		Description:         "Used to manage Keyfactor Command Security Roles using the V2 `/Security/Roles` API. This resource is compatible with Keyfactor Command versions 11+. For more information about this construct, please refer to the API documentation for Security Roles: https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/SecurityRolesandIdentities.htm",
		MarkdownDescription: "Used to manage Keyfactor Command Security Roles using the V2 `/Security/Roles` API. This resource is compatible with Keyfactor Command versions 11+. For more information about this construct, please refer to the [API documentation for Security Roles](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/SecurityRolesandIdentities.htm).\n\n~> **Note on claim associations:** Claim bindings managed by `keyfactor_oauth_security_role_claim_association` are preserved automatically during role updates. Do not manage claims directly on this resource if you are using separate association resources — doing so will cause conflicts.",
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

	state, ok := getState[OAuthSecurityRole](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("OAuth security role from state: ID %d...", state.ID.Value))

	roleId := int32(state.ID.Value)

	tflog.Debug(ctx, fmt.Sprintf("Parsed role ID: %d", roleId))

	tflog.SetField(ctx, "role_id", roleId)

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewGetSecurityRolesByIdRequest(ctx, roleId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security role %d...", roleId))

	remoteState, httpReq, err := req.Execute()

	if err != nil {
		if httpReq != nil {
			tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))
			if httpReq.StatusCode == 404 {
				tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
				response.State.RemoveResource(ctx)
				return
			}
			var body []byte
			if httpReq != nil {
				defer httpReq.Body.Close()
				body, _ = io.ReadAll(httpReq.Body)
			}
			response.Diagnostics.AddError(
				"Error reading security role",
				fmt.Sprintf("Could not read OAuth security role ID %d , unexpected error: %s. Details %s ", roleId, err.Error(), string(body)),
			)
		} else {
			response.Diagnostics.AddError(
				"Error reading security role",
				fmt.Sprintf("Could not read OAuth security role ID %d , unexpected error: %s", roleId, err.Error()),
			)
		}
		return
	}

	if httpReq != nil {
		tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))
	}

	var result = mapOAuthSecurityRole(ctx, remoteState)
	tflog.Debug(ctx, "Data source was able to read OAuth security role resource from remote source using ID")

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
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
	plan, ok := getPlan[OAuthSecurityRole](ctx, &request.Plan, &response.Diagnostics)
	if !ok {
		return
	}

	// Get current state
	state, ok := getState[OAuthSecurityRole](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	roleName := plan.Name.Value
	roleId := int32(state.ID.Value)

	var permissions []string
	plan.Permissions.ElementsAs(ctx, &permissions, false)
	sort.Strings(permissions)

	api := r.p.sdkClient.V2.SecurityRolesApi

	// Read the current role from the server to preserve claims that are
	// managed by the keyfactor_oauth_security_role_claim_association resource.
	// The PUT endpoint replaces the entire role; omitting Claims would wipe
	// all claim associations.
	currentRole, httpGet, errGet := api.NewGetSecurityRolesByIdRequest(ctx, roleId).Execute()
	if errGet != nil {
		var body []byte
		if httpGet != nil {
			defer httpGet.Body.Close()
			body, _ = io.ReadAll(httpGet.Body)
		}
		response.Diagnostics.AddError(
			"Error reading security role before update",
			fmt.Sprintf("Could not read OAuth security role ID %d before update, unexpected error: %s. Details %s", roleId, errGet.Error(), string(body)),
		)
		return
	}

	// Preserve existing claims from the server.
	existingClaims, ok := mapOAuthSecurityClaimsFromRole(ctx, &response.Diagnostics, currentRole, nil)
	if !ok {
		return
	}

	req := api.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
		Id:              roleId,
		Name:            roleName,
		Description:     plan.Description.Value,
		EmailAddress:    *v2.NewNullableString(&plan.EmailAddress.Value),
		PermissionSetId: plan.PermissionSetId.Value,
		Permissions:     permissions,
		Claims:          *existingClaims,
	})

	tflog.Debug(ctx, fmt.Sprintf("Updating OAuth security role with ID: %d, name: %s;\n\tDescription: %s;\n\tEmailAddress: %s;\nt\tPermissionSetId: %s", roleId, roleName, plan.Description.Value, plan.EmailAddress.Value, plan.PermissionSetId.Value))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role..."))

	updateResponse, http, err := req.Execute()
	if err != nil {
		var body []byte
		if http != nil {
			defer http.Body.Close()
			body, _ = io.ReadAll(http.Body)
		}

		response.Diagnostics.AddError(
			"Error updating security role",
			fmt.Sprintf("Could not update OAuth security role ID %d , unexpected error: %s. Details %s ", roleId, err.Error(), string(body)),
		)
		return
	}

	var result = mapOAuthSecurityRole(ctx, updateResponse)
	tflog.Debug(ctx, "Saving OAuth security role resource information into state...")

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
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
	state, ok := getState[OAuthSecurityRole](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	roleId := int32(state.ID.Value)
	tflog.SetField(ctx, "role_id", roleId)

	tflog.Debug(ctx, fmt.Sprintf("Deleting OAuth security role ID %d...", roleId))

	api := r.p.sdkClient.V1.SecurityRolesApi
	req := api.NewDeleteSecurityRolesByIdRequest(ctx, roleId)

	http, err := req.Execute()

	if err != nil {
		var body []byte
		if http != nil {
			defer http.Body.Close()
			body, _ = io.ReadAll(http.Body)
		}

		response.Diagnostics.AddError(
			"Error deleting security role",
			fmt.Sprintf("Could not delete OAuth security role ID %d , unexpected error: %s. Details %s ", roleId, err.Error(), string(body)),
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
	ok := checkIfProviderIsConfigured(r.p, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Info(ctx, "Create called on OAuth security role resource")
	plan, ok := getPlan[OAuthSecurityRole](ctx, &request.Plan, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Extracted Terraform plan: %+v", plan))

	roleName := plan.Name.Value

	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, fmt.Sprintf("Creating OAuth security role with name: %s", roleName))

	var permissions []string
	plan.Permissions.ElementsAs(ctx, &permissions, false)
	sort.Strings(permissions)

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewCreateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleCreationRequest(v2.SecuritySecurityRolesSecurityRoleCreationRequest{
		Name:            roleName,
		Description:     plan.Description.Value,
		EmailAddress:    *v2.NewNullableString(&plan.EmailAddress.Value),
		PermissionSetId: plan.PermissionSetId.Value,
		Permissions:     permissions,
	})

	tflog.Debug(ctx, fmt.Sprintf("Creating OAuth security role with name: %s;\n\tDescription: %s;\n\tEmailAddress: %s;\nt\tPermissionSetId: %s", roleName, plan.Description.Value, plan.EmailAddress.Value, plan.PermissionSetId.Value))

	tflog.Debug(ctx, fmt.Sprintf("Calling remote server to create OAuth security role..."))

	createResponse, http, err := req.Execute()
	if err != nil {
		var body []byte
		if http != nil {
			defer http.Body.Close()
			body, _ = io.ReadAll(http.Body)
		}
		response.Diagnostics.AddError(
			"Error creating security role",
			fmt.Sprintf("Could not create OAuth security role %s , unexpected error: %s. Details %s ", roleName, err.Error(), string(body)),
		)
		return
	}

	if createResponse.Id == nil {
		response.Diagnostics.AddError(
			"Error creating security role",
			"API response missing Id field — role may have been created remotely but cannot be tracked in state.",
		)
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("Successfully created OAuth security role. Role ID: %d", *createResponse.Id))

	var result = mapOAuthSecurityRole(ctx, createResponse)

	tflog.Debug(ctx, "Saving OAuth security role resource information into state...")

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
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

	roleName := request.ID

	tflog.Debug(ctx, fmt.Sprintf("OAuth security role name requested: %s...", roleName))

	tflog.SetField(ctx, "role_name", roleName)

	remoteRoleQuery, err := getSecurityRoleByName(ctx, r.p.sdkClient, roleName)

	if err != nil {
		response.Diagnostics.AddError(
			"Error importing security role",
			fmt.Sprintf("Could not import OAuth security role name %s , an error occurred querying security role: %s.", roleName, err.Error()),
		)
		return
	}

	if remoteRoleQuery.Id == nil {
		response.Diagnostics.AddError(
			"Error importing security role",
			fmt.Sprintf("Query for role %s returned a response with no Id.", roleName),
		)
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("Successfully queried security role %s. Role ID: %d", roleName, *remoteRoleQuery.Id))

	roleId := *remoteRoleQuery.Id

	api := r.p.sdkClient.V2.SecurityRolesApi
	req := api.NewGetSecurityRolesByIdRequest(ctx, roleId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security role %d...", roleId))

	remoteState, httpReq, err := req.Execute()

	if err != nil {
		if httpReq != nil {
			tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))
			if httpReq.StatusCode == 404 {
				tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
				response.State.RemoveResource(ctx)
				return
			}
			var body []byte
			if httpReq != nil {
				defer httpReq.Body.Close()
				body, _ = io.ReadAll(httpReq.Body)
			}
			response.Diagnostics.AddError(
				"Error importing security role",
				fmt.Sprintf("Could not import OAuth security role ID %d , unexpected error: %s. Details %s ", roleId, err.Error(), string(body)),
			)
		} else {
			response.Diagnostics.AddError(
				"Error importing security role",
				fmt.Sprintf("Could not import OAuth security role ID %d , unexpected error: %s", roleId, err.Error()),
			)
		}
		return
	}

	if httpReq != nil {
		tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))
	}

	var result = mapOAuthSecurityRole(ctx, remoteState)
	tflog.Debug(ctx, "Data source was able to import state of OAuth security role resource from remote source using ID")

	ok := updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Debug(ctx, "OAuth security role resource imported successfully.")
}
