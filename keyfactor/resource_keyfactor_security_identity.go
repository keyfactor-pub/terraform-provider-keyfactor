package keyfactor

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
				Optional: true,
				Computed: true,
				Description: "An array of role names or numeric role IDs that the identity is attached to. " +
					"Role names are matched case-insensitively against Keyfactor Command's role names, so a " +
					"declared spelling that only differs in case from the server is not reported as drift. " +
					"Omit to leave role membership unmanaged (preserved on update); set [] explicitly to " +
					"remove all roles.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.UseStateForUnknown(),
				},
			},
			"id": {
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
		Description: "IMPORTANT: This endpoint is for managing legacy formatted Active Directory identities only and" +
			" is retained for backwards compatibility. New applications should use the Security Claims resource for both Active Directory and other identity providers.",
		DeprecationMessage: "This endpoint is for managing legacy formatted Active Directory identities only and is retained for backwards compatibility. New applications should use the Security Claims resource for both Active Directory and other identity providers.",
	}, nil
}

// New resource instance
func (r resourceSecurityIdentityType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceSecurityIdentity{
		p: *(p.(*provider)),
	}, nil
}

type resourceSecurityIdentity struct {
	p provider
}

func (r resourceSecurityIdentity) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	var state SecurityIdentity
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on security identity resource")
	identityId := state.ID.Value
	accountName := state.AccountName.Value
	tflog.SetField(ctx, "id", identityId)

	identities, err := r.p.client.GetSecurityIdentities()

	if err != nil {
		response.Diagnostics.AddError(
			"Error listing identities from Keyfactor.",
			"Error reading identities: "+err.Error(),
		)
	}

	for _, identity := range identities {
		//if int64(identity.Id) == identityId {
		//	tflog.Info(ctx, fmt.Sprintf("Found identity with id: %s", identityId))
		//	break
		//}
		if accountName == identity.AccountName {
			tflog.Info(ctx, fmt.Sprintf("Found identity with account name: %s", accountName))

			// identityRolesResultForRead builds the roles list from the
			// freshly-fetched identity.Roles when it genuinely differs from
			// the prior state (so real server-side role drift -- roles
			// changed out-of-band -- is detected, unlike the old code which
			// just echoed back whatever was already in state), but preserves
			// the prior state's declared spelling/order when the role sets
			// are semantically the same (case-insensitive name or numeric
			// ID), so Read doesn't itself manufacture a spurious diff by
			// rewriting a user's declared casing/ID-form to Command's
			// canonical name.
			state = SecurityIdentity{
				ID:           types.Int64{Value: int64(identity.Id)},
				AccountName:  types.String{Value: identity.AccountName},
				IdentityType: types.String{Value: identity.IdentityType},
				Roles:        identityRolesResultForRead(state.Roles, identity.Roles),
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

// identityRolesDeclared reports whether the config explicitly declares the
// roles attribute. A Null value means the user omitted it from config
// (preserve existing assignments), while a non-null value — including an
// explicit empty list — is a full-replace instruction (an empty list clears
// all roles).
//
// This must be evaluated against the CONFIG, not the plan. roles is
// Optional+Computed (with a UseStateForUnknown plan modifier, added to fix
// "Provider produced inconsistent result after apply" when an unrelated
// Update omitted roles from config): when the attribute is genuinely
// undeclared, Terraform Core still resolves request.Plan.Roles to the prior
// state's value (copied forward by the plan modifier so the CLI doesn't show
// spurious "(known after apply)" noise on every unrelated plan). Checking
// plan.Roles.Null here would therefore always be false, indistinguishable
// from a real declaration of the same list. request.Config.Roles is never
// touched by plan modifiers, so it still reports Null exactly when the user
// omitted the attribute.
func identityRolesDeclared(config SecurityIdentity) bool {
	return !config.Roles.Null && !config.Roles.Unknown
}

// identityRolesCanonical builds a types.List of the server's canonical role
// names, for writing server-reported roles into state when they genuinely
// differ from the prior state.
func identityRolesCanonical(serverRoles []api.SecurityRoleInformation) types.List {
	elems := make([]attr.Value, 0, len(serverRoles))
	for _, role := range serverRoles {
		elems = append(elems, types.String{Value: role.Name})
	}
	return types.List{ElemType: types.StringType, Elems: elems}
}

// identityRolesResultForRead decides what to write into state's Roles after
// Read: if the prior state's role list is semantically equal to the server's
// role list -- every state entry matched bijectively to a distinct server
// role, either by numeric role ID or by case-insensitive role name -- the
// prior state is returned VERBATIM, preserving the user's declared
// spelling/order/ID-vs-name form. Otherwise the server's canonical role names
// are returned, so genuine out-of-band role drift (a role added, removed, or
// actually renamed) surfaces on the next plan instead of being silently
// overwritten by Read.
//
// This mirrors permissionsResultForUpdate's order-vs-drift invariant
// (resource_keyfactor_security_role.go) applied to security_identity's roles
// attribute: the roles schema description documents that entries may be role
// names OR numeric role IDs, and that role names match case-insensitively
// (GetSecurityRole's lookup and Command's role names themselves are
// case-insensitive), so a declared casing difference or ID-vs-name form must
// not be reported as drift merely because Read rewrote it to the server's
// spelling.
//
// A Null/Unknown stateRoles (nothing declared/known yet) has nothing to
// preserve and always returns the server's canonical names. A state list
// whose length doesn't match the server's, or that contains an element that
// cannot be bijectively matched to a distinct server role, is treated as
// real drift and also returns the server's canonical names.
func identityRolesResultForRead(stateRoles types.List, serverRoles []api.SecurityRoleInformation) types.List {
	if stateRoles.Null || stateRoles.Unknown {
		return identityRolesCanonical(serverRoles)
	}
	if len(stateRoles.Elems) != len(serverRoles) {
		return identityRolesCanonical(serverRoles)
	}

	// Require a bijective (1:1) match: each server role may satisfy at most
	// one state entry, so duplicate/ambiguous entries can't false-positive a
	// match against a single server role.
	claimed := make([]bool, len(serverRoles))
	for _, elem := range stateRoles.Elems {
		s, ok := elem.(types.String)
		if !ok {
			return identityRolesCanonical(serverRoles)
		}

		matched := false
		if id, err := strconv.Atoi(s.Value); err == nil {
			for i, role := range serverRoles {
				if !claimed[i] && role.Id == id {
					claimed[i] = true
					matched = true
					break
				}
			}
		}
		if !matched {
			for i, role := range serverRoles {
				if !claimed[i] && strings.EqualFold(role.Name, s.Value) {
					claimed[i] = true
					matched = true
					break
				}
			}
		}
		if !matched {
			return identityRolesCanonical(serverRoles)
		}
	}

	return stateRoles
}

func (r resourceSecurityIdentity) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// Get plan values
	var plan SecurityIdentity
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get config values. roles is Optional+Computed, so request.Plan.Roles is
	// no longer a reliable signal of whether the user declared the attribute
	// (see identityRolesDeclared's doc comment) — request.Config.Roles is.
	var config SecurityIdentity
	diags = request.Config.Get(ctx, &config)
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

	// setIdentityRole is a full-replace sync of the identity's role assignments.
	// Only run it when the plan explicitly declares the roles attribute. When
	// roles is genuinely undeclared (Null) — the user simply omitted it from
	// config — Null must not be conflated with an explicit empty list; the former
	// preserves the identity's existing roles, the latter clears them. Running
	// the full-replace sync on an undeclared Null plan stripped every real role
	// assignment on any unrelated Update.
	result := SecurityIdentity{
		ID:           types.Int64{Value: int64(state.ID.Value)},
		AccountName:  types.String{Value: state.AccountName.Value},
		IdentityType: types.String{Value: state.IdentityType.Value},
		Valid:        types.Bool{Value: state.Valid.Value},
		Roles:        state.Roles,
	}

	if identityRolesDeclared(config) {
		// Generate API request body from plan. Every declared role MUST
		// resolve to a real Keyfactor role before setIdentityRole is ever
		// called: setIdentityRole performs a full-replace sync of the
		// identity's role membership, so silently dropping a role here (e.g.
		// on a lookup error or "not found") would cause setIdentityRole to
		// actively REVOKE the identity's existing membership in that role —
		// a silent access change on what looks like a successful apply. A
		// lookup failure for a declared role must fail the apply with
		// nothing mutated, matching this project's standing rule that
		// transient/lookup errors are surfaced, never swallowed.
		var validRolesInterface []interface{}
		for _, role := range plan.Roles.Elems {
			tflog.Info(ctx, fmt.Sprintf("Adding role: %s", role))

			// Use the role's underlying string value directly. role.String()
			// returns the framework's %q-quoted representation, and the old
			// `[^\w]` sanitizer stripped more than just the surrounding
			// quotes -- it also stripped spaces and hyphens from legitimate
			// role names (e.g. "Power Users" -> "PowerUsers"), causing the
			// lookup below to look for a role that doesn't exist.
			roleVal, ok := role.(types.String)
			if !ok {
				response.Diagnostics.AddError(
					"Unexpected role value type.",
					fmt.Sprintf("Expected role element to be a string, got %T.", role),
				)
				return
			}
			roleStr := roleVal.Value
			tflog.Debug(ctx, fmt.Sprintf("Looking up role %v in Keyfactor", roleStr))
			kfRole, roleLookupErr := r.p.client.GetSecurityRole(roleStr)
			if roleLookupErr != nil {
				response.Diagnostics.AddError(
					"Error looking up role on Keyfactor.",
					fmt.Sprintf(
						"Error looking up role '%s' on Keyfactor: %s. Update aborted before applying any role changes to '%s' to avoid silently revoking its existing role membership.",
						roleStr,
						roleLookupErr.Error(),
						state.AccountName.Value,
					),
				)
				return
			}
			if kfRole == nil {
				response.Diagnostics.AddError(
					"Role not found on Keyfactor.",
					fmt.Sprintf(
						"Role '%s' declared for identity '%s' was not found on Keyfactor. Update aborted before applying any role changes to avoid silently revoking existing role membership.",
						roleStr,
						state.AccountName.Value,
					),
				)
				return
			}
			validRolesInterface = append(validRolesInterface, kfRole.Id)
		}

		//Update role identities (full-replace; an explicit empty list clears them)
		err := setIdentityRole(ctx, r.p.client, state.AccountName.Value, validRolesInterface)
		if err != nil {
			response.Diagnostics.AddError("Error updating identity roles.", "Error updating identity roles: "+err.Error())
			return
		}
		result.Roles = plan.Roles
	}

	// Set state
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityIdentity) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
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
			ERR_SUMMARY_IDENTITY_DELETE,
			"Could not delete "+state.AccountName.Value+" from Keyfactor Command: "+err.Error(),
		)
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceSecurityIdentity) Create(
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

	// The identity has ALREADY been created on Keyfactor Command by this point
	// (createResponse is a real response from a completed POST). Build the
	// baseline result now so that any error encountered while resolving/applying
	// the declared roles below can still persist a tracked, if incomplete,
	// resource -- mirroring this repo's precedent for "already created
	// upstream, but a later step failed" (see the certificate deployment
	// resource's Create(), which persists tainted state on a failed post-submit
	// job wait rather than leaving a Command-side object with no Terraform
	// record at all). Losing this identity out of state entirely would be
	// strictly worse than surfacing an error alongside a resource the user can
	// still see, re-apply, import, or destroy.
	//
	// Roles starts at an empty list, not plan.Roles: at this point in Create no
	// role has actually been granted yet (setIdentityRole is only called below,
	// after every declared role has resolved), so an empty list is the only
	// value that doesn't overclaim what actually happened on the server.
	result := SecurityIdentity{
		ID:           types.Int64{Value: int64(createResponse.Id)},
		AccountName:  types.String{Value: accountName},
		IdentityType: types.String{Value: plan.IdentityType.Value},
		Valid:        types.Bool{Value: plan.Valid.Value},
		Roles:        types.List{ElemType: types.StringType, Elems: []attr.Value{}},
	}

	if len(plan.Roles.Elems) > 0 {
		// Every declared role MUST resolve to a real Keyfactor role before
		// setIdentityRole is ever called -- mirrors Update()'s round-1 fix (see
		// its comment above for the full rationale: silently dropping an
		// unresolvable role here previously let it disappear from
		// validRolesInterface while state still recorded the full declared
		// list as granted, a silent gap between state and reality). Unlike
		// Update(), the identity here has already been created, so a lookup
		// failure can't "abort before mutating anything" -- it aborts before
		// granting ANY of the declared roles, and persists the tainted
		// `result` above (identity tracked in state, zero roles) so the
		// failure is unambiguous and nothing is silently claimed granted.
		var validRolesInterface []interface{}
		for _, role := range plan.Roles.Elems {
			tflog.Info(ctx, fmt.Sprintf("Adding role: %s", role))

			// Use the role's underlying string value directly -- see the
			// matching fix in Update() for why the old `[^\w]` regex
			// sanitizer over role.String() mangled legitimate role names
			// (e.g. names containing spaces or hyphens).
			roleVal, ok := role.(types.String)
			if !ok {
				response.Diagnostics.AddError(
					"Unexpected role value type.",
					fmt.Sprintf("Expected role element to be a string, got %T.", role),
				)
				stateDiags := response.State.Set(ctx, result)
				response.Diagnostics.Append(stateDiags...)
				return
			}
			roleStr := roleVal.Value
			tflog.Debug(ctx, fmt.Sprintf("Looking up role %v in Keyfactor", roleStr))
			kfRole, roleLookupErr := r.p.client.GetSecurityRole(roleStr)
			if roleLookupErr != nil {
				response.Diagnostics.AddError(
					"Error looking up role on Keyfactor.",
					fmt.Sprintf(
						"Identity '%s' (id %d) was created on Keyfactor, but looking up declared role '%s' failed: %s. "+
							"No roles have been granted. Re-apply once the role can be resolved, or remove the resource "+
							"from state (`terraform state rm`) if the identity is no longer needed.",
						accountName, createResponse.Id, roleStr, roleLookupErr.Error(),
					),
				)
				stateDiags := response.State.Set(ctx, result)
				response.Diagnostics.Append(stateDiags...)
				return
			}
			if kfRole == nil {
				response.Diagnostics.AddError(
					"Role not found on Keyfactor.",
					fmt.Sprintf(
						"Identity '%s' (id %d) was created on Keyfactor, but declared role '%s' was not found. "+
							"No roles have been granted. Re-apply once the role exists, or remove the resource from "+
							"state (`terraform state rm`) if the identity is no longer needed.",
						accountName, createResponse.Id, roleStr,
					),
				)
				stateDiags := response.State.Set(ctx, result)
				response.Diagnostics.Append(stateDiags...)
				return
			}
			validRolesInterface = append(validRolesInterface, kfRole.Id)
		}

		err = setIdentityRole(ctx, kfClient, identityArg.AccountName, validRolesInterface)
		if err != nil {
			response.Diagnostics.AddError(
				"Error updating identity roles.",
				fmt.Sprintf(
					"Identity '%s' (id %d) was created on Keyfactor, but syncing its role assignments failed: %s. "+
						"Role membership may be partially applied. Re-apply to retry, or verify role membership manually.",
					accountName, createResponse.Id, err.Error(),
				),
			)
			stateDiags := response.State.Set(ctx, result)
			response.Diagnostics.Append(stateDiags...)
			return
		}
		result.Roles = plan.Roles
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceSecurityIdentity) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	ctx = context.WithValue(ctx, "import", true)
	var state SecurityIdentity

	tflog.Info(ctx, "Read called on security identity resource")
	accountName := request.ID

	identities, err := r.p.client.GetSecurityIdentities()

	if err != nil {
		response.Diagnostics.AddError(
			"Error listing identities from Keyfactor.",
			"Error reading identities: "+err.Error(),
		)
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
		response.Diagnostics.AddError(
			"Unknown identity error.",
			fmt.Sprintf("Unable to find identity %s on Keyfactor. Import failed.", accountName),
		)
		return
	}

	diags := response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

// roleIdToInt converts a role identifier value -- as stored in the
// []interface{} that Create/Update build from kfRole.Id (see
// api.GetSecurityRoleResponse.Id, github.com/Keyfactor/keyfactor-go-client/
// v3/api/security_models.go) -- into an int.
//
// This is a regression fix: GetSecurityRoleResponse.Id is declared as
// float64 (both the by-name and by-ID GetSecurityRole lookup branches
// populate it that way), so every role ID flowing through setIdentityRole
// was actually a float64, never an int. The prior code's type switch
// (`case int: ...; case string, interface{}: roleId = role.(int)`) matched
// float64 via the `interface{}` catch-all and then blindly asserted it to
// int, which panics for any non-int dynamic type -- meaning ANY
// Create/Update that resolved at least one role successfully would crash
// `terraform apply`. This handles both int (defensive, in case a caller ever
// passes one directly) and float64, and returns an error instead of
// panicking for any other unexpected type.
func roleIdToInt(role interface{}) (int, error) {
	switch v := role.(type) {
	case int:
		return v, nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("unexpected role identifier type %T (value %v); expected int or float64", role, role)
	}
}

func setIdentityRole(
	ctx context.Context,
	kfClient *api.Client,
	identityAccountName string,
	roleIds []interface{},
) error {
	// Basic idea here is that we want to sync the output of the GET identity endpoint with the roleIds passed to
	// this function. This could mean that we are removing the identity from a role, adding an identity, or not making
	// any change. This is required because no PUT endpoint exists for /identity.

	// Start by blindly adding the identity to each role.
	if len(roleIds) > 0 {
		for _, role := range roleIds {
			roleId, convErr := roleIdToInt(role)
			if convErr != nil {
				return convErr
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
		xId, convErr := roleIdToInt(x)
		if convErr != nil {
			return convErr
		}
		list[strconv.Itoa(xId)] = struct{}{}
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
	updateArg := &api.UpdateSecurityRoleArg{
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
	updateArg := &api.UpdateSecurityRoleArg{
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
