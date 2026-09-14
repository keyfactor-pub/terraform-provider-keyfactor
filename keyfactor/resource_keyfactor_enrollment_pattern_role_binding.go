package keyfactor

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceEnrollmentPatternRoleBindingType struct{}

func (r resourceEnrollmentPatternRoleBindingType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		MarkdownDescription: `
Binds a single security role to an enrollment pattern using the "/EnrollmentPatterns" API.

Use one ` + "`keyfactor_enrollment_pattern_role_binding`" + ` resource per (enrollment pattern, role) pair. This resource uses a GET-modify-PUT-verify retry loop to safely manage role membership alongside concurrent bindings on the same pattern.

~> **Important:** Enrollment Patterns and this resource are only available in Keyfactor Command v25.0+

~> **Concurrency note:** Command's enrollment pattern PUT endpoint replaces the full role list atomically at the server; there is no per-role sub-endpoint. This resource uses a GET-modify-PUT-verify retry loop (up to 5 attempts with jittered backoff) to reduce — but not eliminate — the lost-update window when two bindings for the same pattern are applied concurrently. For best results, avoid running more than one ` + "`terraform apply`" + ` concurrently against the same enrollment pattern.
`,
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: `Composite key "<enrollment_pattern_name>//<role_name>", stable across imports.`,
			},
			"enrollment_pattern_name": {
				Type:          types.StringType,
				Required:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Name of the enrollment pattern to bind the role to. Changing this value forces a new resource.",
			},
			"role_name": {
				Type:          types.StringType,
				Required:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Name of the security role to bind. Changing this value forces a new resource.",
			},
		},
	}, nil
}

func (r resourceEnrollmentPatternRoleBindingType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceEnrollmentPatternRoleBinding{p: *(p.(*provider))}, nil
}

type resourceEnrollmentPatternRoleBinding struct {
	p provider
}

func (r resourceEnrollmentPatternRoleBinding) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	ok := checkIfProviderIsConfigured(r.p, &response.Diagnostics)
	if !ok {
		return
	}

	tflog.Info(ctx, "Create called on enrollment pattern role binding resource")

	plan, ok := getPlan[EnrollmentPatternRoleBinding](ctx, &request.Plan, &response.Diagnostics)
	if !ok {
		return
	}

	patternName := plan.EnrollmentPatternName.Value
	roleName := plan.RoleName.Value

	tflog.SetField(ctx, "enrollment_pattern_name", patternName)
	tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, fmt.Sprintf("Creating enrollment pattern role binding: pattern=%q role=%q", patternName, roleName))

	// Resolve the pattern name to an ID once (outside the retry loop; the
	// ID is stable and looking it up on every retry wastes a round-trip).
	foundPattern, err := getEnrollmentPatternByName(ctx, r.p.sdkClient, patternName)
	if err != nil {
		response.Diagnostics.AddError(
			"Error resolving enrollment pattern by name.",
			fmt.Sprintf("Could not find enrollment pattern %q: %s", patternName, err.Error()),
		)
		return
	}
	patternID := foundPattern.GetId()

	patternApi := r.p.sdkClient.V1.EnrollmentPatternApi

	// GET-modify-PUT-verify retry loop: Command's enrollment pattern PUT
	// endpoint replaces the full AssociatedRoles list (no atomic per-role
	// sub-endpoint exists -- confirmed by inspection of the v25 SDK's
	// EnrollmentPatternApi method list). Two concurrent Create calls on the
	// same pattern can both GET before either PUTs; the second PUT wins and
	// silently drops the first call's addition. reconcileWithRetry detects
	// this via the verify GET and retries with jittered backoff.
	created, lastErr := reconcileWithRetry(ctx, func(attempt int) (reconcileOutcome, error) {
		currentResp, httpResp, err := patternApi.NewGetEnrollmentPatternsByIdRequest(ctx, patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
		if err != nil {
			if httpResp != nil && httpResp.StatusCode == 404 {
				response.Diagnostics.AddError(
					"Enrollment pattern not found.",
					fmt.Sprintf("Enrollment pattern %q (ID %d) no longer exists.", patternName, patternID),
				)
			} else {
				response.Diagnostics.AddError(
					"Error reading enrollment pattern.",
					fmt.Sprintf("Could not read enrollment pattern %q (ID %d): %s", patternName, patternID, err.Error()),
				)
			}
			return reconcileFatal, nil
		}

		// Idempotency: if the role is already present, nothing left to do.
		if enrollmentPatternHasRole(currentResp, roleName) {
			tflog.Debug(ctx, fmt.Sprintf("Role %q already present on enrollment pattern %q -- skipping PUT", roleName, patternName))
			return reconcileDone, nil
		}

		// Add the role to the current list.
		currentRoles := extractEnrollmentPatternRoleNames(currentResp)
		newRoles := append(currentRoles, roleName) //nolint:gocritic // intentional append-to-external slice

		// Build a full update request preserving all other fields.
		epState := enrollmentPatternResponseToState(currentResp)
		updateBody := buildEnrollmentPatternUpdateRequest(ctx, epState, newRoles)

		tflog.Debug(ctx, fmt.Sprintf("Calling remote server to add role %q to enrollment pattern %q (attempt %d/%d)...", roleName, patternName, attempt, reconcileMaxAttempts))

		_, httpResp2, err := patternApi.NewUpdateEnrollmentPatternsByIdRequest(ctx, patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			EnrollmentPatternsEnrollmentPatternRequest(updateBody).
			Execute()
		if err != nil {
			if httpResp2 != nil && httpResp2.StatusCode == 404 {
				response.Diagnostics.AddError(
					"Enrollment pattern not found during update.",
					fmt.Sprintf("Enrollment pattern %q (ID %d) disappeared during role binding creation.", patternName, patternID),
				)
				return reconcileFatal, nil
			}
			var body []byte
			if httpResp2 != nil {
				body, _ = io.ReadAll(httpResp2.Body)
				httpResp2.Body.Close()
			}
			response.Diagnostics.AddError(
				"Error updating enrollment pattern.",
				fmt.Sprintf("Could not add role %q to enrollment pattern %q: %s. Details: %s", roleName, patternName, err.Error(), string(body)),
			)
			return reconcileFatal, nil
		}

		// Verify: a fresh GET confirms the change stuck and wasn't clobbered
		// by a concurrent writer whose PUT landed between our PUT and now.
		verifyResp, httpResp3, err := patternApi.NewGetEnrollmentPatternsByIdRequest(ctx, patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
		if err != nil {
			if httpResp3 != nil && httpResp3.StatusCode == 404 {
				response.Diagnostics.AddError(
					"Enrollment pattern not found during verification.",
					fmt.Sprintf("Enrollment pattern %q (ID %d) disappeared during role binding verification.", patternName, patternID),
				)
			} else {
				response.Diagnostics.AddError(
					"Error verifying enrollment pattern role binding.",
					fmt.Sprintf("Could not verify addition of role %q to enrollment pattern %q: %s", roleName, patternName, err.Error()),
				)
			}
			return reconcileFatal, nil
		}

		if enrollmentPatternHasRole(verifyResp, roleName) {
			return reconcileDone, nil
		}

		return reconcileRetry, fmt.Errorf("role %q was not present on enrollment pattern %q after PUT+verify (attempt %d/%d) -- a concurrent writer likely overwrote it", roleName, patternName, attempt, reconcileMaxAttempts)
	})

	if !created && !response.Diagnostics.HasError() {
		response.Diagnostics.AddError(
			"Error creating enrollment pattern role binding (concurrent write contention).",
			fmt.Sprintf(
				"Could not add role %q to enrollment pattern %q after %d attempts: %s. "+
					"Another writer is repeatedly modifying this pattern's roles at the same time; retry once contention subsides.",
				roleName, patternName, reconcileMaxAttempts, lastErr,
			),
		)
		return
	}
	if !created {
		return
	}

	result := EnrollmentPatternRoleBinding{
		ID:                    types.String{Value: fmt.Sprintf("%s//%s", patternName, roleName)},
		EnrollmentPatternName: types.String{Value: patternName},
		RoleName:              types.String{Value: roleName},
	}

	tflog.Debug(ctx, fmt.Sprintf("Enrollment pattern role binding created: pattern=%q role=%q", patternName, roleName))

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Info(ctx, "Enrollment pattern role binding created successfully.")
}

func (r resourceEnrollmentPatternRoleBinding) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	tflog.Info(ctx, "Read called on enrollment pattern role binding resource")

	state, ok := getState[EnrollmentPatternRoleBinding](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	patternName := state.EnrollmentPatternName.Value
	roleName := state.RoleName.Value

	tflog.SetField(ctx, "enrollment_pattern_name", patternName)
	tflog.SetField(ctx, "role_name", roleName)

	// Resolve by name on every Read: the name is the stable key practitioners
	// hold, and it doubles as the drift-detection mechanism (if the pattern
	// was renamed or deleted out-of-band, Read removes this binding from state
	// rather than silently leaving stale state behind).
	foundPattern, err := getEnrollmentPatternByName(ctx, r.p.sdkClient, patternName)
	if err != nil {
		// Pattern no longer exists (deleted out-of-band) -- remove from state.
		tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %q not found; removing role binding from state: %s", patternName, err.Error()))
		response.State.RemoveResource(ctx)
		return
	}

	if !enrollmentPatternHasRole(foundPattern, roleName) {
		// Role is no longer associated (removed out-of-band) -- remove from state.
		tflog.Info(ctx, fmt.Sprintf("Role %q no longer present on enrollment pattern %q; removing binding from state", roleName, patternName))
		response.State.RemoveResource(ctx)
		return
	}

	tflog.Debug(ctx, "Enrollment pattern role binding confirmed present on server")

	// State is unchanged -- just confirm it's still correct.
	result := EnrollmentPatternRoleBinding{
		ID:                    types.String{Value: fmt.Sprintf("%s//%s", patternName, roleName)},
		EnrollmentPatternName: types.String{Value: patternName},
		RoleName:              types.String{Value: roleName},
	}

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Debug(ctx, "Enrollment pattern role binding resource read successfully.")
}

func (r resourceEnrollmentPatternRoleBinding) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// All attributes are ForceNew -- any change destroys and re-creates.
	// NOOP.
}

func (r resourceEnrollmentPatternRoleBinding) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on enrollment pattern role binding resource")

	state, ok := getState[EnrollmentPatternRoleBinding](ctx, &request.State, &response.Diagnostics)
	if !ok {
		return
	}

	patternName := state.EnrollmentPatternName.Value
	roleName := state.RoleName.Value

	tflog.SetField(ctx, "enrollment_pattern_name", patternName)
	tflog.SetField(ctx, "role_name", roleName)
	tflog.Debug(ctx, fmt.Sprintf("Deleting enrollment pattern role binding: pattern=%q role=%q", patternName, roleName))

	// Resolve the pattern name to an ID once before the retry loop.
	foundPattern, err := getEnrollmentPatternByName(ctx, r.p.sdkClient, patternName)
	if err != nil {
		// Pattern no longer exists -- the binding is already gone.
		tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %q not found during delete; treating as already removed: %s", patternName, err.Error()))
		return
	}
	patternID := foundPattern.GetId()

	patternApi := r.p.sdkClient.V1.EnrollmentPatternApi

	// GET-modify-PUT-verify retry loop -- see Create()'s identical loop for
	// the full rationale. Mirrors the claim association resource's Delete shape.
	deleted, lastErr := reconcileWithRetry(ctx, func(attempt int) (reconcileOutcome, error) {
		currentResp, httpResp, err := patternApi.NewGetEnrollmentPatternsByIdRequest(ctx, patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
		if err != nil {
			if httpResp != nil && httpResp.StatusCode == 404 {
				tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %q (ID %d) not found; treating as already removed", patternName, patternID))
				return reconcileDone, nil
			}
			response.Diagnostics.AddError(
				"Error reading enrollment pattern.",
				fmt.Sprintf("Could not read enrollment pattern %q (ID %d) before role removal: %s", patternName, patternID, err.Error()),
			)
			return reconcileFatal, nil
		}

		// Idempotency: if the role is already absent, nothing left to do.
		if !enrollmentPatternHasRole(currentResp, roleName) {
			tflog.Debug(ctx, fmt.Sprintf("Role %q already absent from enrollment pattern %q -- skipping PUT", roleName, patternName))
			return reconcileDone, nil
		}

		// Remove the role from the current list. Use case-insensitive
		// comparison to match the same normalisation applied by
		// enrollmentPatternHasRole: if Command stored "Admin" and the
		// practitioner wrote "admin", an exact-match filter would leave the
		// role in the list and the verify step would see it as still present.
		currentRoles := extractEnrollmentPatternRoleNames(currentResp)
		newRoles := make([]string, 0, len(currentRoles))
		for _, r := range currentRoles {
			if !strings.EqualFold(r, roleName) {
				newRoles = append(newRoles, r)
			}
		}

		// Build a full update request preserving all other fields.
		epState := enrollmentPatternResponseToState(currentResp)
		updateBody := buildEnrollmentPatternUpdateRequest(ctx, epState, newRoles)

		tflog.Debug(ctx, fmt.Sprintf("Calling remote server to remove role %q from enrollment pattern %q (attempt %d/%d)...", roleName, patternName, attempt, reconcileMaxAttempts))

		_, httpResp2, err := patternApi.NewUpdateEnrollmentPatternsByIdRequest(ctx, patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			EnrollmentPatternsEnrollmentPatternRequest(updateBody).
			Execute()
		if err != nil {
			if httpResp2 != nil && httpResp2.StatusCode == 404 {
				tflog.Info(ctx, fmt.Sprintf("Enrollment pattern %q (ID %d) disappeared during role removal; treating as removed", patternName, patternID))
				return reconcileDone, nil
			}
			var body []byte
			if httpResp2 != nil {
				body, _ = io.ReadAll(httpResp2.Body)
				httpResp2.Body.Close()
			}
			response.Diagnostics.AddError(
				"Error updating enrollment pattern.",
				fmt.Sprintf("Could not remove role %q from enrollment pattern %q: %s. Details: %s", roleName, patternName, err.Error(), string(body)),
			)
			return reconcileFatal, nil
		}

		// Verify the change stuck.
		verifyResp, httpResp3, err := patternApi.NewGetEnrollmentPatternsByIdRequest(ctx, patternID).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
		if err != nil {
			if httpResp3 != nil && httpResp3.StatusCode == 404 {
				// Pattern gone -- binding is certainly removed.
				return reconcileDone, nil
			}
			response.Diagnostics.AddError(
				"Error verifying enrollment pattern role removal.",
				fmt.Sprintf("Could not verify removal of role %q from enrollment pattern %q: %s", roleName, patternName, err.Error()),
			)
			return reconcileFatal, nil
		}

		if !enrollmentPatternHasRole(verifyResp, roleName) {
			tflog.Debug(ctx, "Enrollment pattern role binding deleted successfully.")
			return reconcileDone, nil
		}

		return reconcileRetry, fmt.Errorf("role %q was still present on enrollment pattern %q after PUT+verify (attempt %d/%d) -- a concurrent writer likely reverted this change", roleName, patternName, attempt, reconcileMaxAttempts)
	})

	if !deleted && !response.Diagnostics.HasError() {
		response.Diagnostics.AddError(
			"Error deleting enrollment pattern role binding (concurrent write contention).",
			fmt.Sprintf(
				"Could not remove role %q from enrollment pattern %q after %d attempts: %s. "+
					"Another writer is repeatedly modifying this pattern's roles at the same time; retry once contention subsides.",
				roleName, patternName, reconcileMaxAttempts, lastErr,
			),
		)
	}
}

// ImportState imports a role binding by its composite ID "<patternName>//<roleName>".
// The "//" delimiter avoids ambiguity when the pattern name contains a colon
// (e.g. "Dept:Finance"). Run: terraform import keyfactor_enrollment_pattern_role_binding.x 'PatternName//RoleName'
func (r resourceEnrollmentPatternRoleBinding) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on enrollment pattern role binding resource")

	parts := strings.SplitN(request.ID, "//", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		response.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected import ID in format '<enrollmentPatternName>//<roleName>', got %q.", request.ID),
		)
		return
	}

	patternName := parts[0]
	roleName := parts[1]

	tflog.SetField(ctx, "enrollment_pattern_name", patternName)
	tflog.SetField(ctx, "role_name", roleName)

	// Verify the binding exists on the server before importing.
	foundPattern, err := getEnrollmentPatternByName(ctx, r.p.sdkClient, patternName)
	if err != nil {
		response.Diagnostics.AddError(
			"Error importing enrollment pattern role binding.",
			fmt.Sprintf("Could not find enrollment pattern %q: %s", patternName, err.Error()),
		)
		return
	}

	if !enrollmentPatternHasRole(foundPattern, roleName) {
		response.Diagnostics.AddError(
			"Role binding not found.",
			fmt.Sprintf("Role %q is not associated with enrollment pattern %q in Keyfactor Command.", roleName, patternName),
		)
		return
	}

	result := EnrollmentPatternRoleBinding{
		ID:                    types.String{Value: fmt.Sprintf("%s//%s", patternName, roleName)},
		EnrollmentPatternName: types.String{Value: patternName},
		RoleName:              types.String{Value: roleName},
	}

	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
}
