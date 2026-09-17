package keyfactor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	v2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
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
				Description:   "Internal ID of the OAuth security role. This is the computed `id` output of a keyfactor_oauth_security_role resource or data source. Changing this value forces a new resource.",
			},
			"claim_id": {
				Type:          types.Int64Type,
				Required:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Internal ID of the OAuth security claim. This is the computed `id` output of a keyfactor_oauth_security_claim resource. Changing this value forces a new resource.",
			},
		},
		Description: "Used to associate an existing OAuth security claim with an existing OAuth security claim resource using the V1 `/Security/Claims/` and V2 `/Security/Roles` APIs. This resource is compatible with Keyfactor Command versions 11+",
		MarkdownDescription: "Used to associate an existing OAuth security claim with an existing OAuth security claim resource using the V1 `/Security/Claims/` and V2 `/Security/Roles` APIs. This resource is compatible with Keyfactor Command versions 11+\n\n" +
			"~> **Where `role_id`/`claim_id` come from:** both are the computed `id` output of their respective resources -- `role_id` from [`keyfactor_oauth_security_role`](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/oauth_security_role), `claim_id` from [`keyfactor_oauth_security_claim`](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/oauth_security_claim) (see that resource's `id` attribute under **Read-Only**). Reference them directly, e.g. `role_id = keyfactor_oauth_security_role.example.id` and `claim_id = keyfactor_oauth_security_claim.example.id`, rather than looking the IDs up out of band.",
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
			fmt.Sprintf("Unknown error while trying to import OAuth security role ID %d from Keyfactor. Read failed. ", roleId)+err.Error(),
		)

		return
	}

	if httpReq != nil {
		tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))
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

	// GET-modify-PUT-verify retry loop: see reconcileWithRetry in helpers.go
	// for why this is necessary (Command's role PUT has no optimistic-
	// concurrency primitive, so a concurrent Create/Delete on a different
	// claim of the same role can silently clobber this change).
	deleted, lastErr := reconcileWithRetry(ctx, func(attempt int) (reconcileOutcome, error, time.Duration) {
		remoteState, httpReq, err := api.NewGetSecurityRolesByIdRequest(ctx, roleId).Execute()
		if err != nil {
			if httpReq != nil && httpReq.StatusCode == 404 {
				tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
				return reconcileDone, nil, 0 // role gone; treat as removed
			}
			if httpReq != nil && httpReq.StatusCode == http.StatusTooManyRequests {
				return reconcileRetry, fmt.Errorf("server returned 429 Too Many Requests on initial GET"), parseRetryAfter(httpReq)
			}
			response.Diagnostics.AddError(
				"Unknown OAuth security role error.",
				fmt.Sprintf("Unknown error while trying to read OAuth security role ID %d from Keyfactor. Read failed. ", roleId)+err.Error(),
			)
			return reconcileFatal, nil, 0
		}

		if !oauthRoleHasClaim(remoteState, claimId) {
			// Already removed (either a prior attempt's PUT stuck, or someone
			// else already removed it). Nothing left to do.
			tflog.Debug(ctx, "OAuth security role claim associated deleted successfully.")
			return reconcileDone, nil, 0
		}

		updatedClaims, ok := mapOAuthSecurityClaimsFromRole(ctx, &response.Diagnostics, remoteState, &claimId)
		if !ok {
			return reconcileFatal, nil, 0
		}
		claims := *updatedClaims

		updateReq := api.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
			Id:              roleId,
			Name:            derefOrEmpty(remoteState.Name.Get()),
			Description:     derefOrEmpty(remoteState.Description.Get()),
			EmailAddress:    remoteState.EmailAddress,
			PermissionSetId: derefOrEmpty(remoteState.PermissionSetId),
			Permissions:     remoteState.Permissions,
			Claims:          claims,
		})

		tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d to remove claim ID %d (attempt %d/%d)...", roleId, claimId, attempt, reconcileMaxAttempts))

		_, httpResp, err := updateReq.Execute()
		if err != nil {
			if httpResp != nil && httpResp.StatusCode == 404 {
				tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
				return reconcileDone, nil, 0
			}
			if httpResp != nil && httpResp.StatusCode == http.StatusTooManyRequests {
				return reconcileRetry, fmt.Errorf("server returned 429 Too Many Requests on PUT"), parseRetryAfter(httpResp)
			}
			var body []byte
			if httpResp != nil {
				body, _ = io.ReadAll(httpResp.Body)
				httpResp.Body.Close()
			}
			response.Diagnostics.AddError(
				"Error updating security role claim association.",
				fmt.Sprintf("Could not update OAuth security role assocation on role ID %d to delete claim ID %d, unexpected error: %s. Details %s ", roleId, claimId, err.Error(), string(body)),
			)
			return reconcileFatal, nil, 0
		}

		// Verify with a fresh GET: catches a concurrent writer's PUT landing
		// between our PUT above and now.
		verifyState, httpReq2, err := api.NewGetSecurityRolesByIdRequest(ctx, roleId).Execute()
		if err != nil {
			if httpReq2 != nil && httpReq2.StatusCode == 404 {
				tflog.Info(ctx, fmt.Sprintf("OAuth Security Role %d not found in remote system. Removing from state", roleId))
				return reconcileDone, nil, 0
			}
			if httpReq2 != nil && httpReq2.StatusCode == http.StatusTooManyRequests {
				return reconcileRetry, fmt.Errorf("server returned 429 Too Many Requests on verify GET"), parseRetryAfter(httpReq2)
			}
			response.Diagnostics.AddError(
				"Unknown OAuth security role error.",
				fmt.Sprintf("Unknown error while trying to verify removal of claim ID %d from OAuth security role ID %d from Keyfactor. ", claimId, roleId)+err.Error(),
			)
			return reconcileFatal, nil, 0
		}

		if !oauthRoleHasClaim(verifyState, claimId) {
			tflog.Debug(ctx, "OAuth security role claim associated deleted successfully.")
			return reconcileDone, nil, 0
		}

		return reconcileRetry, fmt.Errorf("claim ID %d was still present on role ID %d after PUT+verify (attempt %d/%d) -- a concurrent writer likely reverted this change", claimId, roleId, attempt, reconcileMaxAttempts), 0
	})

	if deleted {
		response.State.RemoveResource(ctx)
		return
	}
	if !response.Diagnostics.HasError() {
		response.Diagnostics.AddError(
			"Error deleting security role claim association (concurrent write contention).",
			fmt.Sprintf(
				"Could not remove claim ID %d from OAuth security role ID %d after %d attempts: %s. Another writer is repeatedly modifying this role's claims at the same time; retry once contention subsides.",
				claimId, roleId, reconcileMaxAttempts, lastErr,
			),
		)
	}
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
	claimRequest := claimsApi.NewGetSecurityClaimsByIdRequest(ctx, claimId)

	tflog.Debug(ctx, fmt.Sprintf("Calling remote source to get OAuth security claim ID %d...", claimId))

	remoteClaimState, httpReq, err := claimRequest.Execute()

	if err != nil {
		response.Diagnostics.AddError(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("Unknown error while trying to import OAuth security claim ID %d from Keyfactor. Read failed. ", claimId)+err.Error(),
		)

		return
	}

	if httpReq != nil {
		tflog.Debug(ctx, fmt.Sprintf("HTTP Status code: %d", httpReq.StatusCode))
	}

	if remoteClaimState == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Unknown OAuth security claim error.",
			fmt.Sprintf("fetching OAuth security claim ID %d", claimId),
		)...)
		return
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

	// The claim definition to add. Built once, since it doesn't change
	// across reconcile attempts.
	temp := v2.SecurityRoleClaimDefinitionsRoleClaimDefinitionRequest{
		ClaimType:                    *claimTypeEnum,
		ClaimValue:                   *remoteClaimState.ClaimValue.Get(),
		ProviderAuthenticationScheme: *provider.AuthenticationScheme.Get(),
		Description:                  *remoteClaimState.Description.Get(),
	}

	// GET-modify-PUT-verify retry loop: see reconcileWithRetry in helpers.go
	// for why this is necessary (Command's role PUT has no optimistic-
	// concurrency primitive, so a concurrent Create/Delete on a different
	// claim of the same role can silently clobber this change).
	created, lastErr := reconcileWithRetry(ctx, func(attempt int) (reconcileOutcome, error, time.Duration) {
		remoteRoleState, httpRespGet, err := roleApi.NewGetSecurityRolesByIdRequest(ctx, roleId).Execute()
		if err != nil {
			if httpRespGet != nil && httpRespGet.StatusCode == http.StatusTooManyRequests {
				return reconcileRetry, fmt.Errorf("server returned 429 Too Many Requests on initial GET"), parseRetryAfter(httpRespGet)
			}
			if httpRespGet != nil && httpRespGet.StatusCode == 404 {
				response.Diagnostics.AddError(
					"OAuth security role not found.",
					fmt.Sprintf("OAuth security role ID %d was not found while creating the claim association. The role may have been deleted.", roleId),
				)
			} else {
				response.Diagnostics.AddError(
					"Unknown OAuth security role error.",
					fmt.Sprintf("Unknown error while trying to read OAuth security role ID %d from Keyfactor. Read failed. ", roleId)+err.Error(),
				)
			}
			return reconcileFatal, nil, 0
		}

		if oauthRoleHasClaim(remoteRoleState, claimId) {
			// Already associated (either a prior attempt's PUT stuck, or
			// someone else already added it). Nothing left to do.
			return reconcileDone, nil, 0
		}

		existingClaims, ok := mapOAuthSecurityClaimsFromRole(ctx, &response.Diagnostics, remoteRoleState, nil)
		if !ok {
			return reconcileFatal, nil, 0
		}
		updatedClaims := addOAuthSecurityClaimToRole(ctx, *existingClaims, temp)

		updateReq := roleApi.NewUpdateSecurityRolesRequest(ctx).SecuritySecurityRolesSecurityRoleUpdateRequest(v2.SecuritySecurityRolesSecurityRoleUpdateRequest{
			Id:              roleId,
			Name:            derefOrEmpty(remoteRoleState.Name.Get()),
			Description:     derefOrEmpty(remoteRoleState.Description.Get()),
			EmailAddress:    remoteRoleState.EmailAddress,
			PermissionSetId: derefOrEmpty(remoteRoleState.PermissionSetId),
			Permissions:     remoteRoleState.Permissions,
			Claims:          updatedClaims,
		})

		tflog.Debug(ctx, fmt.Sprintf("Calling remote server to update OAuth security role ID %d to add security claim id %d (attempt %d/%d)...", roleId, claimId, attempt, reconcileMaxAttempts))

		_, httpResp2, err := updateReq.Execute()
		if err != nil {
			if httpResp2 != nil && httpResp2.StatusCode == http.StatusTooManyRequests {
				return reconcileRetry, fmt.Errorf("server returned 429 Too Many Requests on PUT"), parseRetryAfter(httpResp2)
			}
			var body []byte
			if httpResp2 != nil {
				body, _ = io.ReadAll(httpResp2.Body)
				httpResp2.Body.Close()
			}
			response.Diagnostics.AddError(
				"Error creating security role claim association.",
				fmt.Sprintf("Could not create OAuth security role assocation on role ID %d to add claim ID %d, unexpected error: %s. Details %s ", roleId, claimId, err.Error(), string(body)),
			)
			return reconcileFatal, nil, 0
		}

		// Verify with a fresh GET: catches a concurrent writer's PUT landing
		// between our PUT above and now.
		verifyState, httpRespVerify, err := roleApi.NewGetSecurityRolesByIdRequest(ctx, roleId).Execute()
		if err != nil {
			if httpRespVerify != nil && httpRespVerify.StatusCode == http.StatusTooManyRequests {
				return reconcileRetry, fmt.Errorf("server returned 429 Too Many Requests on verify GET"), parseRetryAfter(httpRespVerify)
			}
			if httpRespVerify != nil && httpRespVerify.StatusCode == 404 {
				response.Diagnostics.AddError(
					"OAuth security role not found.",
					fmt.Sprintf("OAuth security role ID %d was deleted while verifying the claim association. The role may have been removed by another process.", roleId),
				)
				return reconcileFatal, nil, 0
			}
			response.Diagnostics.AddError(
				"Unknown OAuth security role error.",
				fmt.Sprintf("Unknown error while trying to verify addition of claim ID %d to OAuth security role ID %d from Keyfactor. ", claimId, roleId)+err.Error(),
			)
			return reconcileFatal, nil, 0
		}

		if oauthRoleHasClaim(verifyState, claimId) {
			return reconcileDone, nil, 0
		}

		return reconcileRetry, fmt.Errorf("claim ID %d was not present on role ID %d after PUT+verify (attempt %d/%d) -- a concurrent writer likely overwrote it", claimId, roleId, attempt, reconcileMaxAttempts), 0
	})

	if !created && !response.Diagnostics.HasError() {
		response.Diagnostics.AddError(
			"Error creating security role claim association (concurrent write contention).",
			fmt.Sprintf(
				"Could not add claim ID %d to OAuth security role ID %d after %d attempts: %s. Another writer is repeatedly modifying this role's claims at the same time; retry once contention subsides.",
				claimId, roleId, reconcileMaxAttempts, lastErr,
			),
		)
	}
	if !created {
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
