package keyfactor

import (
	"context"
	"fmt"
	"slices"
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
				Computed:            true,
				Description:         "An array containing the permissions assigned to the role in a list of Name:Value pairs. Omitting this attribute leaves permissions unmanaged/preserved (server-side changes are not corrected); an explicit empty list ([]) declaratively clears all permissions.",
				MarkdownDescription: "An array containing the permissions assigned to the role in a list of Name:Value pairs. For more information about allowed permission values, please refer to the Keyfactor Command [Version One Permission Model documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityRolePermissions.htm#Version1). Omitting this attribute leaves permissions unmanaged/preserved (server-side changes are not corrected); an explicit empty list (`[]`) declaratively clears all permissions.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.UseStateForUnknown(),
				},
			},
		},
		Description:         "IMPORTANT:  This has been deprecated since it supports Active Directory identities only. It is retained for backwards compatibility, but all new development should use methods that provide support for alternate identity providers and the newer claims-based authentication model that accompanies this. These newer methods support both Active Directory and other identity providers. See version 2 of this resource. NOTE: Read performs a live lookup against Keyfactor Command on every plan/refresh; a role deleted outside Terraform is removed from state and planned for re-creation.",
		MarkdownDescription: "IMPORTANT:  This has been deprecated since it supports Active Directory identities only. It is retained for backwards compatibility, but all new development should use methods that provide support for alternate identity providers and the newer claims-based authentication model that accompanies this. These newer methods support both Active Directory and other identity providers. See version 2 of this resource, `keyfactor_oauth_security_role`. NOTE: Read performs a live lookup against Keyfactor Command on every plan/refresh; a role deleted outside Terraform is removed from state and planned for re-creation.",
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
		// GetSecurityRole converts an HTTP 404 into a non-nil Go error (see
		// vendor/.../keyfactor-go-client/v3/api/client.go's sendRequest,
		// which returns errors.New(body["Message"]) for 404s -- no
		// structured status code is preserved on this call path). A role
		// deleted out-of-band in Command must not brick every subsequent
		// plan/refresh/destroy; detect the not-found signature the same way
		// resource_keyfactor_certificate_store_type.go's Read does for this
		// same api.Client style, and remove the resource from state instead
		// of erroring, so Terraform plans a re-create. Any other error (5xx,
		// auth, network) still fails Read.
		if isNotFoundError(err) {
			// roleName is logged %q-quoted (escaping embedded control
			// characters like \r\n) rather than with %s, so a role name
			// crafted to contain a CRLF sequence can't forge fake log lines
			// under TF_LOG=INFO (CWE-117 log injection); see the identical
			// rationale on roleLookupLogMessage in
			// resource_keyfactor_security_identity.go. roleId is a numeric
			// types.Int64 value, not attacker-controlled text, so it is left
			// as %v.
			tflog.Info(ctx, fmt.Sprintf("Security role %q (id %v) not found on Keyfactor, removing from state", roleName, roleId))
			response.State.RemoveResource(ctx)
			return
		}
		response.Diagnostics.AddError(
			"Error reading role from Keyfactor.",
			fmt.Sprintf("Unknown error while trying to read role %q (id %v) on Keyfactor. Read failed. ", roleName, roleId)+err.Error(),
		)
		return
	}
	if remoteState == nil {
		// A (nil, nil) response is GetSecurityRole's other not-found shape
		// (its string-lookup branch falls off the loop with no match and
		// returns nil, nil with no error at all) -- treat it identically to
		// the 404 case above.
		tflog.Info(ctx, fmt.Sprintf("Security role %q (id %v) not found on Keyfactor, removing from state", roleName, roleId))
		response.State.RemoveResource(ctx)
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
// plan, given the permissions value to treat as authoritative for "did the
// user declare this attribute" (see the call site in Update() -- this must be
// request.Config.Permissions, not request.Plan.Permissions, now that
// permissions is Optional+Computed; see permissionsResultForUpdate's doc
// comment for why), and a permissions value to fall back to when the
// attribute is undeclared.
//
// Command's PUT /Security/Roles is a full-replace endpoint, NOT a merge
// patch: confirmed live against a real Command instance, a PUT body that
// simply omits the "Permissions" key entirely (as opposed to sending
// "Permissions": null) still resets the role's permissions to an empty list
// server-side. (This differs from how Command treats Enabled/Private, which
// ARE preserved when omitted -- Permissions gets special-cased clear-if-absent
// handling server-side.) So leaving the Permissions field nil/omitted on the
// request can never mean "leave unchanged" for this endpoint; the only way to
// preserve the role's existing permissions across an Update that omits
// `permissions` from config is to resend them explicitly.
//
// A Null declaredPermissions value means the user omitted the attribute, so
// statePermissions is sent instead. Despite the parameter name (kept for
// signature stability), the caller must pass a fresh-from-server permissions
// value here, NOT Terraform's prior state -- state can be stale relative to
// the live server (e.g. an out-of-band permission change made directly in
// Command, or a plan applied with -refresh=false), and sending it would
// silently revert a real permission change back to the stale value on any
// unrelated Update. See the call site in Update() for the fresh value this
// is sourced from. An explicit empty list is a real clear signal and is sent
// as `[]`.
func buildSecurityRoleUpdateArg(ctx context.Context, plan SecurityRole, declaredPermissions types.List, statePermissions types.List, roleId int) (*api.UpdateSecurityRoleArg, diag.Diagnostics) {
	arg := &api.UpdateSecurityRoleArg{
		Id: roleId,
		CreateSecurityRoleArg: api.CreateSecurityRoleArg{
			Name:        plan.Name.Value,
			Description: plan.Description.Value,
		},
	}

	permsSource := declaredPermissions
	if permsSource.Null || permsSource.Unknown {
		permsSource = statePermissions
	}

	permissions := []string{}
	var diags diag.Diagnostics
	if !permsSource.Null && !permsSource.Unknown {
		diags = permsSource.ElementsAs(ctx, &permissions, false)
		if diags.HasError() {
			return nil, diags
		}
	}
	if permissions == nil {
		permissions = []string{}
	}
	sort.Strings(permissions)
	arg.Permissions = &permissions
	return arg, diags
}

// securityIdentitiesToRoleConfig converts a role's current server-reported
// Identities (api.SecurityIdentity, as returned by GetSecurityRole) into the
// []api.SecurityRoleIdentityConfig shape UpdateSecurityRoleArg.Identities
// expects, so Update() can resend a role's existing identity bindings
// unchanged. Mirrors the identical conversion already done in
// addIdentityToRole / removeIdentityFromRole (see
// resource_keyfactor_security_identity.go).
func securityIdentitiesToRoleConfig(identities []api.SecurityIdentity) *[]api.SecurityRoleIdentityConfig {
	result := make([]api.SecurityRoleIdentityConfig, len(identities))
	for i, identity := range identities {
		result[i] = api.SecurityRoleIdentityConfig{AccountName: identity.AccountName}
	}
	return &result
}

// permissionSetsEqual compares two permission slices as sets — order-
// insensitive, but case-SENSITIVE (Command permission strings are
// case-sensitive, e.g. "Certificates:Read").
func permissionSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aSorted := slices.Clone(a)
	bSorted := slices.Clone(b)
	slices.Sort(aSorted)
	slices.Sort(bSorted)
	return slices.Equal(aSorted, bSorted)
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
// after a successful Update: it must preserve planPermissions verbatim
// (declared order intact) when the server's response reports the same set of
// permissions -- regardless of order -- avoiding the alphabetical-resort
// drift bug this preserves against. But it must NOT mask genuine server-side
// permission drift (Command rejecting/normalizing/dropping a permission): if
// the server's reported set differs from the plan's, the server's
// permissions are written instead, so real drift surfaces on the next plan.
//
// A Null/Unknown planPermissions (permissions undeclared) has nothing to
// preserve the order of, so it is always treated as "sets differ" and the
// server's permissions win.
//
// permissions is Optional+Computed (with a UseStateForUnknown plan modifier,
// added to fix "Provider produced inconsistent result after apply" when an
// unrelated Update omitted permissions from config): the Update() call site
// must pass request.Config.Permissions here, NOT request.Plan.Permissions.
// Once the modifier is in place, an omitted-from-config Plan value is no
// longer null -- Terraform Core resolves it to the prior state's value so the
// CLI doesn't show spurious "(known after apply)" noise on every unrelated
// plan -- so checking Plan would misclassify "omitted" as "explicitly
// re-declared the same list", and buildSecurityRoleUpdateArg would start
// sending an unnecessary Permissions payload on every Update. Config is never
// touched by plan modifiers, so it still reports Null exactly when the user
// omitted the attribute.
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

	// Get config values. permissions is Optional+Computed, so
	// request.Plan.Permissions is no longer a reliable signal of whether the
	// user declared the attribute (see permissionsResultForUpdate's doc
	// comment) -- request.Config.Permissions is.
	var config SecurityRole
	diags = request.Config.Get(ctx, &config)
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

	// Command's PUT /Security/Roles is a full-replace endpoint -- Identities
	// is a *[]T `json:"Identities,omitempty"` field on CreateSecurityRoleArg
	// (embedded in UpdateSecurityRoleArg), exactly the same shape as
	// Permissions, and subject to the identical clear-on-omit behavior
	// documented on buildSecurityRoleUpdateArg above. Unlike Permissions,
	// though, keyfactor_security_role has no `identities` attribute in its
	// schema at all -- identities are only ever attached to a role
	// out-of-band (directly in Command, or via keyfactor_security_identity's
	// addIdentityToRole/removeIdentityFromRole helpers in
	// resource_keyfactor_security_identity.go) -- so there is no
	// Terraform-state-tracked value to fall back on here. The only source of
	// truth is a fresh server read, fetched and resent unchanged: the exact
	// pattern addIdentityToRole/removeIdentityFromRole already use to avoid
	// this same clear-on-omit trap. Without this, applying ANY unrelated
	// change to this resource (permissions, description) would silently wipe
	// every identity/group bound to the role, with no diagnostic.
	remoteRole, err := r.p.client.GetSecurityRole(int(roleId))
	if err != nil {
		// %q-quoted for the same CWE-117 reason as Read() above.
		response.Diagnostics.AddError(
			"Error reading role from Keyfactor.",
			fmt.Sprintf("Unable to read role %q (id %v) from Keyfactor before update: ", state.Name.Value, roleId)+err.Error(),
		)
		return
	}
	if remoteRole == nil {
		// %q-quoted for the same CWE-117 reason as Read() above.
		response.Diagnostics.AddError(
			"Error reading role from Keyfactor.",
			fmt.Sprintf("Role %q (id %v) not found on Keyfactor while preparing update.", state.Name.Value, roleId),
		)
		return
	}

	// Generate API request body from plan. remoteRole.Permissions -- the
	// fresh server read fetched two lines above (the same call already used
	// to source Identities below) -- is passed as the fallback so that when
	// config.Permissions is undeclared, buildSecurityRoleUpdateArg can resend
	// the role's current permissions explicitly rather than omitting the
	// field -- Command's PUT endpoint clears permissions when the field is
	// absent, it does not treat absence as "leave unchanged" (see
	// buildSecurityRoleUpdateArg's doc comment). Terraform's prior state
	// (state.Permissions) is deliberately NOT used here: it can be stale
	// relative to the live server, and resending a stale value would
	// silently revert a real out-of-band permission change on any Update
	// that only touches an unrelated field (e.g. description) -- the same
	// staleness trap the fresh GetSecurityRole call above was added to avoid
	// for Identities.
	updateArg, diags2 := buildSecurityRoleUpdateArg(ctx, plan, config.Permissions, permissionsToTfList(remoteRole.Permissions), int(roleId))
	response.Diagnostics.Append(diags2...)
	if response.Diagnostics.HasError() {
		return
	}
	updateArg.Identities = securityIdentitiesToRoleConfig(remoteRole.Identities)

	remoteState, err := r.p.client.UpdateSecurityRole(updateArg)
	if err != nil {
		// %q-quoted for the same CWE-117 reason as Read() above.
		response.Diagnostics.AddError(
			"Identity role update error.",
			fmt.Sprintf("Error updating identity role %q: ", plan.Name.Value)+err.Error(),
		)
		return
	}

	// resultPermissions is the final resolved permission list -- the one
	// actually written to state below -- not raw config/prior-state, so the
	// debug log below reflects what the role ends up with after Update, same
	// as ImportState's equivalent per-permission log line.
	resultPermissions := permissionsResultForUpdate(ctx, config.Permissions, remoteState.Permissions)
	for _, v := range resultPermissions.Elems {
		if perm, ok := v.(types.String); ok {
			tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm.Value))
		}
	}

	var result = SecurityRole{
		ID:          types.Int64{Value: int64(state.ID.Value)},
		Name:        types.String{Value: remoteState.Name},
		Description: types.String{Value: remoteState.Description},
		Permissions: resultPermissions,
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

	// permissions is Optional+Computed: when the user omits it from config,
	// plan.Permissions arrives Unknown (there's no prior state yet for
	// UseStateForUnknown to copy forward from during Create). ElementsAs on
	// an Unknown or Null list returns an error diagnostic, so guard the call
	// and leave permissions as an explicit empty slice (not nil) in that
	// case instead of erroring out of Create entirely -- a nil slice, even
	// wrapped in the non-nil *[]string below, still marshals as JSON "null"
	// (encoding/json only omits/collapses on the pointer, not the slice
	// itself), which is the same clear-vs-omit trap documented on
	// buildSecurityRoleUpdateArg; an explicit []string{} marshals as "[]",
	// matching a freshly-created role's true "no permissions declared" state.
	permissions := []string{}
	if !plan.Permissions.Unknown && !plan.Permissions.Null {
		diags = plan.Permissions.ElementsAs(ctx, &permissions, false)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	}
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

	// permissions is Optional+Computed: when config omits it entirely,
	// plan.Permissions arrives Unknown (there's no prior state yet for
	// UseStateForUnknown to copy forward from during Create). A
	// freshly-created role genuinely has no permissions unless declared, so
	// resolve Unknown to a concrete empty list rather than writing an Unknown
	// value into state, which Terraform Core would reject.
	resultPermissions := plan.Permissions
	if resultPermissions.Unknown {
		resultPermissions = permissionsToTfList(nil)
	}

	var result = SecurityRole{
		ID:          types.Int64{Value: int64(createResponse.Id)},
		Name:        types.String{Value: createResponse.Name},
		Description: types.String{Value: createResponse.Description},
		Permissions: resultPermissions,
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
				"Unknown error while trying to import role '%v' on Keyfactor. Read failed. ",
				roleId,
			)+err.Error(),
		)
		return
	}

	for _, perm := range remoteState.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
	}

	var result = SecurityRole{
		ID:          types.Int64{Value: int64(remoteState.Id)},
		Name:        types.String{Value: remoteState.Name},
		Description: types.String{Value: remoteState.Description},
		Permissions: permissionsToTfList(remoteState.Permissions),
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
