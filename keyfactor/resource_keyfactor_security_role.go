package keyfactor

import (
	"context"
	"fmt"
	"sort"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
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
			"id": {
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
				Type:                types.ListType{ElemType: types.StringType},
				Optional:            true,
				Description:         "An array containing the permissions assigned to the role in a list of Name:Value pairs",
				MarkdownDescription: "An array containing the permissions assigned to the role in a list of Name:Value pairs. For more information about allowed permission values, please refer to the Keyfactor Command [Version One Permission Model documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityRolePermissions.htm#Version1).",
			},
		},
		Description:         "IMPORTANT:  This has been deprecated since it supports Active Directory identities only. It is retained for backwards compatibility, but all new development should use methods that provide support for alternate identity providers and the newer claims-based authentication model that accompanies this. These newer methods support both Active Directory and other identity providers. See version 2 of this resource.",
		MarkdownDescription: "IMPORTANT:  This has been deprecated since it supports Active Directory identities only. It is retained for backwards compatibility, but all new development should use methods that provide support for alternate identity providers and the newer claims-based authentication model that accompanies this. These newer methods support both Active Directory and other identity providers. See version 2 of this resource, `keyfactor_oauth_security_role`.",
		DeprecationMessage:  "This has been deprecated since it supports Active Directory identities only. It is retained for backwards compatibility, but all new development should use methods that provide support for alternate identity providers and the newer claims-based authentication model that accompanies this. These newer methods support both Active Directory and other identity providers. See version 2 of this resource, 'keyfactor_oauth_security_role'.",
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

func (r resourceSecurityRole) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	var state SecurityRole
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on security role resource")
	roleId := state.ID.Value
	roleName := state.Name.Value
	tflog.SetField(ctx, "role_id", roleId)

	remoteState, err := r.p.client.GetSecurityRole(int(roleId))
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading role from Keyfactor.",
			fmt.Sprintf("Unknown error while trying to read role '%s' (id %v) on Keyfactor. Read failed. ", roleName, roleId)+err.Error(),
		)
		return
	}
	if remoteState == nil {
		response.Diagnostics.AddError(
			"Unknown role error.",
			fmt.Sprintf("Unable to find role '%s' (id %v) on Keyfactor. Read failed.", roleName, roleId),
		)
		return
	}

	// permissionsResultForUpdate preserves the plan/state's declared order
	// when the server's permission set is unchanged, but surfaces the
	// server's permissions when the set genuinely differs -- this is the
	// same order-vs-drift invariant Update relies on (see doc comment
	// above), applied here so Read can detect real out-of-band permission
	// changes without introducing a spurious alphabetical-resort diff.
	result := SecurityRole{
		ID:          types.Int64{Value: int64(remoteState.Id)},
		Name:        types.String{Value: remoteState.Name},
		Description: types.String{Value: remoteState.Description},
		Permissions: permissionsResultForUpdate(ctx, state.Permissions, &remoteState.Permissions),
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

// buildSecurityRoleUpdateArg builds the UpdateSecurityRole request from the
// plan. permissions is Optional (not Computed): a Null value means the user
// omitted the attribute and the existing permissions must be preserved, so the
// Permissions field is left nil and omitted from the request (the `omitempty`
// pointer fires). Previously a Null plan resolved to a nil Go slice that was
// still wrapped in a non-nil pointer (&permissions); the non-nil pointer
// bypassed omitempty and marshaled as `"Permissions": null`, telling Command to
// clear every permission the role had. An explicit empty list is a real clear
// signal and is sent as `[]`.
func buildSecurityRoleUpdateArg(ctx context.Context, plan SecurityRole, roleId int) *api.UpdateSecurityRoleArg {
	arg := &api.UpdateSecurityRoleArg{
		Id: roleId,
		CreateSecurityRoleArg: api.CreateSecurityRoleArg{
			Name:        plan.Name.Value,
			Description: plan.Description.Value,
		},
	}
	if !plan.Permissions.Null && !plan.Permissions.Unknown {
		permissions := []string{}
		plan.Permissions.ElementsAs(ctx, &permissions, false)
		if permissions == nil {
			permissions = []string{}
		}
		sort.Strings(permissions)
		arg.Permissions = &permissions
	}
	return arg
}

// permissionSetsEqual compares two permission slices as sets — order-
// insensitive, but case-SENSITIVE (Command permission strings are
// case-sensitive, e.g. "Certificates:Read").
func permissionSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aSorted := append([]string{}, a...)
	bSorted := append([]string{}, b...)
	sort.Strings(aSorted)
	sort.Strings(bSorted)
	for i := range aSorted {
		if aSorted[i] != bSorted[i] {
			return false
		}
	}
	return true
}

// permissionsToTfList builds a types.List of permission strings, for writing
// server-reported permissions into state when they genuinely differ from the
// plan.
func permissionsToTfList(permissions []string) types.List {
	result := types.List{ElemType: types.StringType, Elems: []attr.Value{}}
	for _, p := range permissions {
		result.Elems = append(result.Elems, types.String{Value: p})
	}
	return result
}

// permissionsResultForUpdate decides what to write into state's Permissions
// after a successful Update: it must preserve plan.Permissions verbatim
// (declared order intact) when the server's response reports the same set of
// permissions -- regardless of order -- avoiding the alphabetical-resort
// drift bug this preserves against. But it must NOT mask genuine server-side
// permission drift (Command rejecting/normalizing/dropping a permission): if
// the server's reported set differs from the plan's, the server's
// permissions are written instead, so real drift surfaces on the next plan.
//
// A Null/Unknown plan (permissions undeclared) has nothing to preserve the
// order of, so it is always treated as "sets differ" and the server's
// permissions win.
func permissionsResultForUpdate(ctx context.Context, planPermissions types.List, remotePermissions *[]string) types.List {
	var remote []string
	if remotePermissions != nil {
		remote = *remotePermissions
	}

	if planPermissions.Null || planPermissions.Unknown {
		return permissionsToTfList(remote)
	}

	var planValues []string
	planPermissions.ElementsAs(ctx, &planValues, false)

	if !permissionSetsEqual(planValues, remote) {
		return permissionsToTfList(remote)
	}

	return planPermissions
}

func (r resourceSecurityRole) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
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
	tflog.SetField(ctx, "id", roleId)

	// Generate API request body from plan
	updateArg := buildSecurityRoleUpdateArg(ctx, plan, int(roleId))

	remoteState, err := r.p.client.UpdateSecurityRole(updateArg)
	if err != nil {
		response.Diagnostics.AddError(
			"Identity role update error.",
			fmt.Sprintf("Error updating identity role '%s': "+err.Error(), plan.Name.Value),
		)
		return
	}

	var result = SecurityRole{
		ID:          types.Int64{Value: int64(state.ID.Value)},
		Name:        types.String{Value: remoteState.Name},
		Description: types.String{Value: remoteState.Description},
		Permissions: permissionsResultForUpdate(ctx, plan.Permissions, remoteState.Permissions),
	}

	// Set state
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityRole) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
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
			ERR_SUMMARY_IDENTITY_DELETE,
			"Could not delete "+state.Name.Value+" from Keyfactor Command: "+err.Error(),
		)
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceSecurityRole) Create(
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
	sort.Strings(permissions)

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

func (r resourceSecurityRole) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "Read called on security remoteState resource")
	roleId := request.ID
	//roleName := state.Name.Value
	tflog.SetField(ctx, "role_id", roleId)
	//_, err := strconv.Atoi(roleId)

	remoteState, err := r.p.client.GetSecurityRole(roleId)
	if remoteState == nil {
		response.Diagnostics.AddError(
			"Unknown role error.",
			fmt.Sprintf("Unable to find role '%v' on Keyfactor. Read failed. ", roleId),
		)
		return
	}

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown role error.",
			fmt.Sprintf(
				"Unknown error while trying to import role '%v' on Keyfactor. Read failed. "+err.Error(),
				roleId,
			),
		)
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
