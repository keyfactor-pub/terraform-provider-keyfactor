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
	"log"
	"regexp"
	"strconv"
	"strings"
)

type resourceSecurityIdentityType struct{}

func (r resourceSecurityIdentityType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"account_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\\\user or group name",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.RequiresReplace(),
				},
			},
			"roles": {
				Type: types.ListType{
					ElemType: types.StringType,
				},
				//Computed:    true,
				Optional:    true,
				Description: "An array containing the role IDs that the identity is attached to.",
			},
			"identity_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer containing the Keyfactor Command identifier for the security identity.",
			},
			"identity_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the type of identity—User or Group.",
			},
			"valid": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that indicates whether the security identity's audit XML is valid (true) or not (false). A security identity may become invalid if Keyfactor Command determines that it appears to have been tampered with.",
			},
		},
	}, nil
}

// New resource instance
func (r resourceSecurityIdentityType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceSecurityIdentity{
		p: *(p.(*provider)),
	}, nil
}

type resourceSecurityIdentity struct {
	p provider
}

func (r resourceSecurityIdentity) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	var state SecurityIdentity
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on security identity resource")
	identityId := state.ID.Value
	accountName := state.AccountName.Value
	tflog.SetField(ctx, "identity_id", identityId)

	identities, err := r.p.client.GetSecurityIdentities()

	if err != nil {
		response.Diagnostics.AddError("Error listing identities from Keyfactor.", "Error reading identities: "+err.Error())
	}

	for _, identity := range identities {
		//if int64(identity.Id) == identityId {
		//	tflog.Info(ctx, fmt.Sprintf("Found identity with id: %s", identityId))
		//	break
		//}
		if accountName == identity.AccountName {
			tflog.Info(ctx, fmt.Sprintf("Found identity with account name: %s", accountName))

			var validRoles []attr.Value
			var validRolesInterface []interface{}
			for _, role := range state.Roles.Elems {
				//validRoles = append(validRoles.Elems, role.Name.Value)
				tflog.Info(ctx, fmt.Sprintf("Adding role: %s", role))
				tflog.Debug(ctx, fmt.Sprintf("Looking up role %v in Keyfactor", role))

				//TODO: Verify role exists in Keyfactor or throw warning
				re, _ := regexp.Compile(`[^\w]`)
				roleStr := re.ReplaceAllString(role.String(), "")
				kfRole, roleLookupErr := r.p.client.GetSecurityRole(roleStr)
				if roleLookupErr != nil || kfRole == nil {
					tflog.Warn(ctx, fmt.Sprintf("Error looking up role %s on Keyfactor.", role))
					response.Diagnostics.AddWarning(
						"Error looking up role on Keyfactor.",
						fmt.Sprintf("Error looking up role '%s' on Keyfactor. '%s' will not have role '%s'.", roleStr, state.AccountName.Value, roleStr),
					)
					continue
				}
				validRoles = append(validRoles, types.String{Value: fmt.Sprintf("%s", roleStr)})
				validRolesInterface = append(validRolesInterface, kfRole.Id)
			}

			state = SecurityIdentity{
				ID:           types.Int64{Value: int64(identity.Id)},
				AccountName:  types.String{Value: identity.AccountName},
				IdentityType: types.String{Value: identity.IdentityType},
				Roles:        types.List{Elems: validRoles, ElemType: types.StringType},
				Valid:        types.Bool{Value: identity.Valid},
			}
			break
		}

	}

	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityIdentity) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	// Get plan values
	var plan SecurityIdentity
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	//kfClient := r.p.client
	tflog.Info(ctx, "Update called on security identity resource")

	// Get current state
	var state SecurityIdentity
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	//var validRoles types.List
	var validRoles []attr.Value
	var validRolesInterface []interface{}
	for _, role := range plan.Roles.Elems {
		//validRoles = append(validRoles.Elems, role.Name.Value)
		tflog.Info(ctx, fmt.Sprintf("Adding role: %s", role))
		tflog.Debug(ctx, fmt.Sprintf("Looking up role %v in Keyfactor", role))

		//TODO: Verify role exists in Keyfactor or throw warning
		re, err := regexp.Compile(`[^\w]`)
		if err != nil {
			log.Fatal(err)
		}
		roleStr := re.ReplaceAllString(role.String(), "")
		fmt.Println(roleStr)
		kfRole, roleLookupErr := r.p.client.GetSecurityRole(roleStr)
		if roleLookupErr != nil || kfRole == nil {
			tflog.Warn(ctx, fmt.Sprintf("Error looking up role %s on Keyfactor.", role))
			response.Diagnostics.AddWarning(
				"Error looking up role on Keyfactor.",
				fmt.Sprintf("Error looking up role '%s' on Keyfactor. '%s' will not have role '%s'.", roleStr, state.AccountName.Value, roleStr),
			)
			continue
		}
		validRoles = append(validRoles, types.String{Value: fmt.Sprintf("%s", roleStr)})
		validRolesInterface = append(validRolesInterface, kfRole.Id)
	}

	//Update role identities
	err := setIdentityRole(ctx, r.p.client, state.AccountName.Value, validRolesInterface)
	if err != nil {
		response.Diagnostics.AddError("Error updating identity roles.", "Error updating identity roles: "+err.Error())
	}

	var result = SecurityIdentity{
		ID:           types.Int64{Value: int64(state.ID.Value)},
		AccountName:  types.String{Value: state.AccountName.Value},
		IdentityType: types.String{Value: state.IdentityType.Value},
		Valid:        types.Bool{Value: state.Valid.Value},
		Roles:        plan.Roles,
	}

	// Set state
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityIdentity) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	var state SecurityIdentity
	diags := request.State.Get(ctx, &state)
	kfClient := r.p.client

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get order ID from state
	identityId := state.ID.Value

	// Delete order by calling API
	err := kfClient.DeleteSecurityIdentity(int(identityId))
	if err != nil {
		response.Diagnostics.AddError(
			"Error deleting security identity.",
			"Could not delete "+state.AccountName.Value+" from Keyfactor: "+err.Error(),
		)
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceSecurityIdentity) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan SecurityIdentity
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	accountName := plan.AccountName.Value
	ctx = tflog.SetField(ctx, "account_name", accountName)
	tflog.Info(ctx, "Creating Keyfactor security identity resource")

	identityArg := &api.CreateSecurityIdentityArg{
		AccountName: accountName,
	}

	createResponse, err := kfClient.CreateSecurityIdentity(identityArg)
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating security identity.",
			"Could not create identity "+plan.AccountName.Value+", unexpected error: "+err.Error(),
		)
		return
	}

	// for more information on logging from providers, refer to
	// https://pkg.go.dev/github.com/hashicorp/terraform-plugin-log/tflog
	tflog.Trace(ctx, "created security id", map[string]interface{}{"identity_account_name": plan.AccountName.Value})
	var validRoles []attr.Value
	if len(plan.Roles.Elems) > 0 {
		var validRolesInterface []interface{}
		for _, role := range plan.Roles.Elems {
			//validRoles = append(validRoles.Elems, role.Name.Value)
			tflog.Info(ctx, fmt.Sprintf("Adding role: %s", role))
			tflog.Debug(ctx, fmt.Sprintf("Looking up role %v in Keyfactor", role))

			//TODO: Verify role exists in Keyfactor or throw warning
			re, _ := regexp.Compile(`[^\w]`)
			roleStr := re.ReplaceAllString(role.String(), "")
			fmt.Println(roleStr)
			kfRole, roleLookupErr := r.p.client.GetSecurityRole(roleStr)
			if roleLookupErr != nil || kfRole == nil {
				tflog.Warn(ctx, fmt.Sprintf("Error looking up role with id: %s", role))
				response.Diagnostics.AddWarning(
					"Error looking up role on Keyfactor.",
					fmt.Sprintf("Error looking up role '%s' on Keyfactor. %s will not have role %s.", roleStr, accountName, roleStr),
				)
				continue
			}
			validRoles = append(validRoles, types.String{Value: fmt.Sprintf("%s", roleStr)})
			validRolesInterface = append(validRolesInterface, kfRole.Id)
		}
		err = setIdentityRole(ctx, kfClient, identityArg.AccountName, validRolesInterface)
		if err != nil {
			response.Diagnostics.AddError("Error updating identity roles.", "Error updating identity roles: "+err.Error())
		}
	}

	if validRoles == nil {
		validRoles = plan.Roles.Elems
	}
	// Generate resource state struct
	var result = SecurityIdentity{
		ID:           types.Int64{Value: int64(createResponse.Id)},
		AccountName:  types.String{Value: accountName},
		IdentityType: types.String{Value: plan.IdentityType.Value},
		Valid:        types.Bool{Value: plan.Valid.Value},
		Roles:        plan.Roles,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityIdentity) ImportState(ctx context.Context, request tfsdk.ImportResourceStateRequest, response *tfsdk.ImportResourceStateResponse) {
	ctx = context.WithValue(ctx, "import", true)
	var state SecurityIdentity
	//diags := request.State.Get(ctx, &state)
	//response.Diagnostics.Append(diags...)
	//if response.Diagnostics.HasError() {
	//	return
	//}

	tflog.Info(ctx, "Read called on security identity resource")
	accountName := request.ID

	identities, err := r.p.client.GetSecurityIdentities()

	if err != nil {
		response.Diagnostics.AddError("Error listing identities from Keyfactor.", "Error reading identities: "+err.Error())
	}

	identityExists := false
	for _, identity := range identities {
		if accountName == identity.AccountName {
			tflog.Info(ctx, fmt.Sprintf("Found identity with account name: %s", accountName))
			identityExists = true
			var roles []attr.Value
			for _, role := range identity.Roles {
				roles = append(roles, types.String{Value: role.Name})
			}
			state = SecurityIdentity{
				ID:           types.Int64{Value: int64(identity.Id)},
				AccountName:  types.String{Value: identity.AccountName},
				IdentityType: types.String{Value: identity.IdentityType},
				Roles:        types.List{Elems: roles, ElemType: types.StringType},
				Valid:        types.Bool{Value: identity.Valid},
			}

			break
		}

	}

	if !identityExists {
		response.Diagnostics.AddError("Unknown identity error.", fmt.Sprintf("Unable to find identity %s on Keyfactor. Import failed.", accountName))
		return
	}

	diags := response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func setIdentityRole(ctx context.Context, kfClient *api.Client, identityAccountName string, roleIds []interface{}) error {
	// Basic idea here is that we want to sync the output of the GET identity endpoint with the roleIds passed to
	// this function. This could mean that we are removing the identity from a role, adding an identity, or not making
	// any change. This is required because no PUT endpoint exists for /identity.

	// Start by blindly adding the identity to each role.
	if len(roleIds) > 0 {
		var roleId int
		for _, role := range roleIds {
			switch role.(type) {
			case int:
				roleId = role.(int)

			case string, interface{}:
				roleId = role.(int)
			}
			err := addIdentityToRole(ctx, kfClient, identityAccountName, roleId)
			if err != nil {
				return err
			}
		}
	}

	// Then, build a list of all roles associated with the identity and make sure that only the ones specified by
	// this function are added.
	// Get all Keyfactor security identities
	identities, err := kfClient.GetSecurityIdentities()
	if err != nil {
		return err
	}
	var identity api.GetSecurityIdentityResponse
	for _, identity = range identities {
		if strings.ToLower(identity.AccountName) == strings.ToLower(identityAccountName) {
			break
		}
	}

	// Now, build a list of the roles associated with the identity. Note that any differences found here will be removals
	// because we already added the roles that we want above. The below method doesn't require the slices to be sorted,
	// and operates at approximately O(n)

	list := make(map[string]struct{}, len(roleIds))
	for _, x := range roleIds {
		list[strconv.Itoa(x.(int))] = struct{}{}
	}
	var diff []int
	for _, x := range identity.Roles {
		if _, found := list[strconv.Itoa(x.Id)]; !found {
			diff = append(diff, x.Id)
		}
	}

	for _, role := range diff {
		err = removeIdentityFromRole(kfClient, identity.AccountName, role)
		if err != nil {
			return err
		}
	}
	return nil
}

func removeIdentityFromRole(kfClient *api.Client, identityAccountName string, roleId int) error {
	log.Printf("[DEBUG] Removing account %s from Keyfactor role %d", identityAccountName, roleId)
	// Construct a list of security identities currently attached to role
	role, err := kfClient.GetSecurityRole(roleId)
	if err != nil {
		return err
	}
	var identityList []api.SecurityRoleIdentityConfig
	for _, identity := range role.Identities {
		if strings.ToLower(identityAccountName) != strings.ToLower(identity.AccountName) {
			temp := api.SecurityRoleIdentityConfig{
				AccountName: identity.AccountName,
			}
			identityList = append(identityList, temp)
		}
	}

	// Note - update security role wraps the create role structure but compiles to the desired JSON request body.
	updateArg := &api.UpdatteSecurityRoleArg{
		Id: roleId,
		CreateSecurityRoleArg: api.CreateSecurityRoleArg{
			Name:        role.Name,
			Identities:  &identityList,
			Description: role.Description,
			Permissions: &role.Permissions,
		},
	}

	_, err = kfClient.UpdateSecurityRole(updateArg)
	if err != nil {
		return err
	}

	return nil
}

func addIdentityToRole(ctx context.Context, kfClient *api.Client, identityAccountName string, roleId int) error {
	ctx = tflog.SetField(ctx, "role_id", roleId)
	ctx = tflog.SetField(ctx, "identity_account_name", identityAccountName)
	tflog.Debug(ctx, "Adding account to Keyfactor role.")
	// Construct a list of security identities currently attached to role
	role, err := kfClient.GetSecurityRole(roleId)
	if err != nil {
		return err
	}

	identityList := make([]api.SecurityRoleIdentityConfig, len(role.Identities))
	for i, identity := range role.Identities {
		if identity.AccountName == identityAccountName {
			tflog.Debug(ctx, "Account is already associated with Keyfactor role.")
			return nil
		}
		temp := api.SecurityRoleIdentityConfig{
			AccountName: identity.AccountName,
		}
		identityList[i] = temp
	}

	// Add new identity to identity list and update role
	temp := api.SecurityRoleIdentityConfig{
		AccountName: identityAccountName,
	}
	identityList = append(identityList, temp)

	// Note - update security role wraps the create role structure but compiles to the desired JSON request body.
	updateArg := &api.UpdatteSecurityRoleArg{
		Id: roleId,
		CreateSecurityRoleArg: api.CreateSecurityRoleArg{
			Name:        role.Name,
			Identities:  &identityList,
			Description: role.Description,
			Permissions: &role.Permissions,
		},
	}

	_, err = kfClient.UpdateSecurityRole(updateArg)
	if err != nil {
		return err
	}

	return nil
}
