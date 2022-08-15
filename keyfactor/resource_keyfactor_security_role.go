package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceSecurityRoleType struct{}

func (r resourceSecurityRoleType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"role_id": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "An string associated with a Keyfactor security role.",
			},
			"description": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the description of the role in Keyfactor",
			},
			"permissions": {
				Type:        types.ListType{ElemType: types.StringType},
				Optional:    true,
				Description: "An array containing the permissions assigned to the role in a list of Name:Value pairs",
			},
		},
	}, nil
}

// New resource instance
func (r resourceSecurityRoleType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceSecurityRole{
		p: *(p.(*provider)),
	}, nil
}

type resourceSecurityRole struct {
	p provider
}

func (r resourceSecurityRole) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	var state SecurityRole
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on security remoteState resource")
	roleId := state.ID.Value
	//roleName := state.Name.Value
	tflog.SetField(ctx, "role_id", roleId)

	//remoteState, err := r.p.client.GetSecurityRole(int(roleId))
	//if remoteState == nil {
	//	response.Diagnostics.AddError("Unknown role error.", fmt.Sprintf("Unable to find role '%s' on Keyfactor. Read failed.", roleName))
	//	return
	//}

	//if err != nil {
	//	response.Diagnostics.AddError("Error listing roles from Keyfactor.", "Error reading roles: "+err.Error())
	//	return
	//}

	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityRole) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	// Get plan values
	var plan SecurityRole
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Update called on security identity resource")

	// Get current state
	var state SecurityRole
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	roleId := state.ID.Value
	tflog.SetField(ctx, "role_id", roleId)

	// Generate API request body from plan

	var permissions []string
	plan.Permissions.ElementsAs(ctx, &permissions, false)
	//Update role identities
	updateArg := &api.UpdateSecurityRoleArg{
		Id: int(roleId),
		CreateSecurityRoleArg: api.CreateSecurityRoleArg{
			Name:        plan.Name.Value,
			Description: plan.Description.Value,
			Permissions: &permissions,
		},
	}

	remoteState, err := r.p.client.UpdateSecurityRole(updateArg)
	if err != nil {
		response.Diagnostics.AddError("Identity role update error.", fmt.Sprintf("Error updating identity role '%s': "+err.Error(), plan.Name.Value))
		return
	}

	var permissionValues []attr.Value
	for _, perm := range *remoteState.Permissions {
		tflog.Info(ctx, "Permission: "+perm)
		permissionValues = append(permissionValues, types.String{
			Value: perm,
		})
	}

	var result = SecurityRole{
		ID:          types.Int64{Value: int64(state.ID.Value)},
		Name:        types.String{Value: remoteState.Name},
		Description: types.String{Value: remoteState.Description},
		Permissions: types.List{ElemType: types.StringType, Elems: permissionValues},
	}

	// Set state
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityRole) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	var state SecurityRole
	diags := request.State.Get(ctx, &state)
	kfClient := r.p.client

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get order ID from state
	identityId := state.ID.Value

	// Delete order by calling API
	err := kfClient.DeleteSecurityRole(int(identityId))
	if err != nil {
		response.Diagnostics.AddError(
			"Error deleting security identity.",
			"Could not delete "+state.Name.Value+" from Keyfactor: "+err.Error(),
		)
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceSecurityRole) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan SecurityRole
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	roleName := plan.Name.Value
	ctx = tflog.SetField(ctx, "role_name", roleName)
	tflog.Info(ctx, "Creating Keyfactor security identity resource")

	var permissions []string
	plan.Permissions.ElementsAs(ctx, &permissions, false)

	roleArg := &api.CreateSecurityRoleArg{
		Name:        roleName,
		Description: plan.Description.Value,
		Permissions: &permissions,
	}

	createResponse, err := kfClient.CreateSecurityRole(roleArg)
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating security identity.",
			"Could not create identity "+plan.Name.Value+", unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, "Created security role", map[string]interface{}{"role_name": plan.Name.Value})
	//var validPermissions []attr.Value
	//var validPermissionsInterface []interface{}
	//if len(plan.Permissions.Elems) > 0 {
	//	var validRolesInterface []interface{}
	//	for _, permission := range plan.Permissions.Elems {
	//		tflog.Info(ctx, fmt.Sprintf("Adding permission: %s", permission))
	//		tflog.Debug(ctx, fmt.Sprintf("Looking up permission %v in Keyfactor", permission))
	//
	//		//TODO: Verify permission exists in Keyfactor or throw warning
	//		re, _ := regexp.Compile(`[^\w]`)
	//		permissionStr := re.ReplaceAllString(permission.String(), "")
	//		fmt.Println(permissionStr)
	//		kfPerm, plErr := kfClient.GetPermission(permissionStr)
	//		if plErr != nil || kfPerm == nil {
	//			tflog.Warn(ctx, fmt.Sprintf("Error looking up permission with id: %s", permission))
	//			response.Diagnostics.AddWarning(
	//				"Error looking up permission on Keyfactor.",
	//				fmt.Sprintf("Error looking up permission '%s' on Keyfactor. %s will not have permission %s.", permissionStr, roleName, permissionStr),
	//			)
	//			continue
	//		}
	//		validPermissions = append(validPermissions, types.String{Value: fmt.Sprintf("%s", permissionStr)})
	//		//validPermissionsInterface = append(validRolesInterface, kfPerm.Name)
	//	}
	//	err = setIdentityRole(ctx, kfClient, roleArg.Name, validRolesInterface)
	//	if err != nil {
	//		response.Diagnostics.AddError("Error updating identity roles.", "Error updating identity roles: "+err.Error())
	//	}
	//}
	//if validPermissions == nil {
	//	validPermissions = plan.Permissions.Elems
	//}

	// Generate resource state struct
	//var permissionValues []attr.Value
	//for perm := range *createResponse.Permissions {
	//	tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
	//	permissionValues = append(permissionValues, types.String{Value: strconv.Itoa(perm)})
	//}
	var result = SecurityRole{
		ID:          types.Int64{Value: int64(createResponse.Id)},
		Name:        types.String{Value: createResponse.Name},
		Description: types.String{Value: createResponse.Description},
		Permissions: plan.Permissions,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityRole) ImportState(ctx context.Context, request tfsdk.ImportResourceStateRequest, response *tfsdk.ImportResourceStateResponse) {
	tflog.Info(ctx, "Read called on security remoteState resource")
	roleId := request.ID
	//roleName := state.Name.Value
	tflog.SetField(ctx, "role_id", roleId)
	//_, err := strconv.Atoi(roleId)

	remoteState, err := r.p.client.GetSecurityRole(roleId)
	if remoteState == nil {
		response.Diagnostics.AddError("Unknown role error.", fmt.Sprintf("Unable to find role '%v' on Keyfactor. Read failed. ", roleId))
		return
	}

	if err != nil {
		response.Diagnostics.AddError("Unknown role error.", fmt.Sprintf("Unknown error while trying to import role '%v' on Keyfactor. Read failed. "+err.Error(), roleId))
		return
	}

	var permissionValues []attr.Value
	for _, perm := range remoteState.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		permissionValues = append(permissionValues, types.String{Value: perm})
	}

	var result = SecurityRole{
		ID:          types.Int64{Value: int64(remoteState.Id)},
		Name:        types.String{Value: remoteState.Name},
		Description: types.String{Value: remoteState.Description},
		Permissions: types.List{ElemType: types.StringType, Elems: permissionValues},
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
