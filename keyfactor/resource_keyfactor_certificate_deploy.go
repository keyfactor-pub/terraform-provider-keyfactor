package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-go-client-sdk/v24"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Orchestrator job Result and Status codes returned by Keyfactor Command's
// GET /OrchestratorJobs/JobHistory endpoint. The API models these as bare
// integers; the mappings below are from the Command reference guide (25.x):
//
//	Result: 4=Failure, 3=Warning, 2=Success, 0=Unknown
//	Status: 5=CompletedWillRetry, 4=Acknowledged, 3=Completed, 2=InProcess, 1=Waiting, 0=Unknown
const (
	orchJobResultSuccess int32 = 2
	orchJobResultWarning int32 = 3
	orchJobResultFailure int32 = 4

	orchJobStatusCompleted          int32 = 3
	orchJobStatusAcknowledged       int32 = 4
	orchJobStatusCompletedWillRetry int32 = 5

	// jobHistoryReturnLimit bounds the /OrchestratorJobs/JobHistory response for a
	// single job ID. Combined with the descending JobHistoryId sort below, the
	// first page reliably contains the latest attempt even for a job that has
	// been retried many times, without relying on the server's undocumented
	// default page size/sort (T4).
	jobHistoryReturnLimit int32 = 100
)

// tfBoolValue returns the value of an optional framework bool attribute,
// treating null/unknown as false.
func tfBoolValue(b types.Bool) bool {
	return !b.Null && !b.Unknown && b.Value
}

// storeHasInventorySchedule reports whether the certificate store storeId has any
// inventory schedule configured (Immediate, Interval, Daily, or ExactlyOnce). When
// the store read itself fails, readErr is returned and hasSchedule is always false —
// callers must distinguish "store read failed" from "store genuinely has no
// schedule" in their own logging/diagnostics rather than conflating the two.
func storeHasInventorySchedule(conn *api.Client, storeId string) (hasSchedule bool, readErr error) {
	storeResp, err := conn.GetCertificateStoreByID(storeId)
	if err != nil {
		return false, err
	}
	sched := storeResp.InventorySchedule
	return sched.Immediate != nil || sched.Interval != nil || sched.Daily != nil || sched.ExactlyOnce != nil, nil
}

// deploymentOverwriteOnCertIDChange is a plan modifier used by the certificate
// deployment resource. It requires that the resource be replaced when the
// `certificate_id` attribute changes unless the top-level `overwrite` attribute
// in the plan is explicitly set to true.
//
// This modifier implements tfsdk.AttributePlanModifier and inspects both the
// current state and the planned value for the attribute at req.AttributePath.
// If both values are known and different and `overwrite` is not true, the
// modifier sets resp.RequiresReplace = true so Terraform will plan a resource
// replacement.
type deploymentOverwriteOnCertIDChange struct{}

// Description returns a brief plain-text description of the plan modifier.
func (m deploymentOverwriteOnCertIDChange) Description(ctx context.Context) string {
	return "Require replace when certificate_id changes unless `overwrite` is true."
}

// MarkdownDescription returns the description suitable for markdown rendering.
func (m deploymentOverwriteOnCertIDChange) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

// Modify examines the plan and state for the target attribute and the top-level
// `overwrite` attribute. If both the old and new certificate_id are known and
// different, and `overwrite` is not set to true in the plan, this method marks
// the attribute as requiring replacement by setting resp.RequiresReplace.
//
// The method is a no-op when either plan or state is missing, or when the
// relevant values are unknown or null.
func (m deploymentOverwriteOnCertIDChange) Modify(
	ctx context.Context,
	req tfsdk.ModifyAttributePlanRequest,
	resp *tfsdk.ModifyAttributePlanResponse,
) {
	// Only act when both plan and state exist
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	// Read overwrite from plan
	var allow types.Bool
	if diags := req.Plan.GetAttribute(ctx, path.Root("overwrite"), &allow); diags.HasError() {
		allow = types.Bool{Null: true}
	}

	// Read old/new certificate_id
	var oldID, newID types.Int64
	_ = req.State.GetAttribute(ctx, req.AttributePath, &oldID)
	_ = req.Plan.GetAttribute(ctx, req.AttributePath, &newID)

	// If either is unknown/null, bail
	if oldID.Unknown || newID.Unknown || oldID.Null || newID.Null {
		return
	}

	changed := oldID.Value != newID.Value
	allowed := !allow.Unknown && !allow.Null && allow.Value

	if changed && !allowed {
		// Older framework: this is a bool, not a slice
		resp.RequiresReplace = true
	}
}

type resourceCommandCertificateDeploymentType struct{}

func (r resourceCommandCertificateDeploymentType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A unique identifier for this certificate deployment.",
			},
			"certificate_id": {
				Type:          types.Int64Type,
				Required:      true,
				Description:   "Keyfactor certificate ID",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"certificate_store_id": {
				Type:          types.StringType,
				Required:      true,
				Description:   "A string containing the GUID for the certificate store to which the certificate should be added.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"certificate_alias": {
				Type:          types.StringType,
				Required:      false,
				Optional:      true,
				Description:   "A string providing an alias to be used for the certificate upon entry into the certificate store. The function of the alias varies depending on the certificate store type. Please ensure that the alias is lowercase, or problems can arise in Terraform Plan. If not provided deployment validation will be done by Command certificate ID.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"key_password": {
				Type:          types.StringType,
				Optional:      true,
				Sensitive:     true,
				Description:   "Password that protects PFX certificate, if the certificate was enrolled using PFX enrollment, or is password protected in general. This value cannot change, and Terraform will throw an error if a change is attempted.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"job_parameters": {
				Type:        types.MapType{ElemType: types.StringType},
				Optional:    true,
				Description: "A map of entry parameters to be passed to the deployment job. These will only be used if the orchestrator extension supports them.",
			},
			"overwrite": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "If set to `true`, updating the `certificate_id` to a different certificate will overwrite the existing certificate in the store. If set to `false` or not set, updating the `certificate_id` will cause the resource to be replaced, and the existing certificate will be removed from the store before the new certificate is added.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"redeploy": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "If true, the certificate will be redeployed to the store. If false, the certificate will be deployed only if it is not already deployed to the store.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.RequiresReplaceIf(
						// The conditional function
						forceIfTrue,
						"Triggers resource replacement when 'redeploy' is set to 'true'.", // Description
						"Triggers resource replacement when `redeploy` is set to `true`.", // Markdown Description
					),
				},
			},
			"skip_removal": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "If set to `true`, deleting the resource will not remove the certificate from the store. Defaults to `false`.",
			},
			"skip_inventory_validation": {
				Type:     types.BoolType,
				Optional: true,
				Description: "If set to `true`, the provider will not poll the certificate store inventory to confirm that a " +
					"deployment (or removal on destroy) completed. The management job is still submitted to Keyfactor Command " +
					"and the single-pass duplicate-deployment pre-check still runs, but the resource completes as soon as the " +
					"job is scheduled. A successful apply therefore does NOT confirm the certificate reached the store — " +
					"combine with `fail_on_job_failure` to still fail the run when the orchestrator reports a job failure. " +
					"Defaults to `false`.",
			},
			"fail_on_job_failure": {
				Type:     types.BoolType,
				Optional: true,
				Description: "If set to `true`, the provider tracks the orchestrator job(s) scheduled by this resource (both " +
					"deployment and removal) via the Keyfactor Command `/OrchestratorJobs/JobHistory` API and fails the " +
					"Terraform run if a job completes with a failure result. Jobs that fail but will be retried by Command " +
					"are waited on until a final result is reached. Requires the authenticated identity to hold the Agent " +
					"Management - Read permission (claim `/agents/management/read/`) in Keyfactor Command. Defaults to `false`.",
			},
		},
		Description: "Used to schedule a certificate deployment(" +
			"/management) job on Keyfactor Command using the `/OrchestratorJobs/Custom` API to deploy certificates to" +
			" `keyfactor_certificate_store` resources. " +
			"*NOTE:* The jobs are run asynchronously, and depend on orchestrator agent check in schedules. By default the provider will wait for the job to complete successfully and may run for a long time. " +
			"Use `skip_inventory_validation` and/or `fail_on_job_failure` to change what a successful apply means: by default success requires the certificate to appear in the store inventory; with `fail_on_job_failure` a failed orchestrator job fails the run early; with `skip_inventory_validation` the resource completes once the job is scheduled (or, combined with `fail_on_job_failure`, once the job itself reports success). " +
			"With `fail_on_job_failure` set, orchestrator job-history messages are surfaced verbatim into Terraform diagnostics and may contain infrastructure detail. " +
			"A resource whose apply failed under `fail_on_job_failure` (e.g. a permission error) still persists tainted state; destroying that resource still requires the same Agent Management - Read permission, since destroy submits its own removal job and polls its status the same way — grant the permission, or remove the resource from state manually (`terraform state rm`) if the removal job is not needed.",
		MarkdownDescription: `
Used to schedule a certificate deployment(/management) job on Keyfactor Command using the "/OrchestratorJobs/Custom"
API to deploy certificates to "keyfactor_certificate_store" resources.

> [!IMPORTANT]
> Orchestrator agent jobs are run asynchronously outside of Terraform, and depend on orchestrator agent check in schedules.
> By default a "keyfactor_certificate_deployment" *will not finish* successfully until the destination certificate store's
> certificate inventory has been updated to include the deployed certificate.

The two opt-in attributes change what a successful apply means:

| skip_inventory_validation | fail_on_job_failure | Behavior after the job is submitted |
|---|---|---|
| false (default) | false (default) | Poll the store inventory until the certificate appears (or warn and return if the store has no inventory schedule). |
| false | true | Poll the orchestrator job and the store inventory together: a failed job fails the run immediately; success still requires the certificate to appear in inventory. Stores with no inventory schedule are validated by job status alone. |
| true | false | Return as soon as Keyfactor Command accepts the job (fire-and-forget). A green apply does not confirm the certificate reached the store. |
| true | true | Poll the orchestrator job until it reaches a final result: success completes the resource, failure fails the run. The store inventory is not consulted. |

> [!NOTE]
> "fail_on_job_failure" requires the Agent Management - Read permission (claim "/agents/management/read/") in Keyfactor
> Command. A job that is never picked up by an orchestrator (e.g. the agent is offline) reports no failure and will
> still be waited on indefinitely. Orchestrator job-history messages surfaced in Terraform diagnostics and logs are
> authored by the orchestrator extension and passed through verbatim, so they may contain infrastructure detail
> (hostnames, paths, internal error text).
> A resource whose apply failed under "fail_on_job_failure" (for example, a permission error while watching the job)
> still persists tainted state so the deployment is not lost. Destroying that resource still requires the same
> Agent Management - Read permission: destroy submits its own removal job and polls its status the same way Create
> does. Grant the permission before destroying, or remove the resource from state manually
> ("terraform state rm") if the removal job itself is not needed.
`,
	}, nil
}

func (r resourceCommandCertificateDeploymentType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceCommandCertificateDeployment{
		p: *(p.(*provider)),
	}, nil
}

type resourceCommandCertificateDeployment struct {
	p provider
}

func (r resourceCommandCertificateDeployment) Create(
	ctx context.Context, request tfsdk.CreateResourceRequest,
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
	var plan CommandCertificateDeployment
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	certificateId := plan.CertificateId.Value
	certificateIdInt := int(certificateId)
	storeId := plan.StoreId.Value
	certificateAlias := plan.CertificateAlias.Value
	//keyPassword := plan.KeyPassword.Value

	overwrite := plan.Overwrite.Value
	forceRedploy := plan.Redeploy.Value

	var jobParams map[string]string
	_ = plan.JobParameters.ElementsAs(ctx, &jobParams, false)
	hid := fmt.Sprintf("%v-%s-%s", certificateId, storeId, certificateAlias)

	// Built once here since every input (hid, plan.*) is available before the
	// duplicate-deployment/job-wait branching below, and reused both for the
	// T2 tainted-state early return and the normal end-of-Create state set —
	// the two call sites were previously identical struct literals (U2).
	result := CommandCertificateDeployment{
		ID:               types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
		CertificateId:    plan.CertificateId,
		StoreId:          plan.StoreId,
		CertificateAlias: plan.CertificateAlias,
		KeyPassword:      plan.KeyPassword,
		JobParameters:    plan.JobParameters,
		Redeploy:         plan.Redeploy,
		Overwrite:        plan.Overwrite,
		SkipRemoval:      plan.SkipRemoval,

		SkipInventoryValidation: plan.SkipInventoryValidation,
		FailOnJobFailure:        plan.FailOnJobFailure,
	}

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	//ctx = tflog.SetField(ctx, "key_password", keyPassword)
	ctx = tflog.SetField(ctx, "overwrite", overwrite)
	ctx = tflog.SetField(ctx, "redeploy", forceRedploy)
	skipInventoryValidation := tfBoolValue(plan.SkipInventoryValidation)
	failOnJobFailure := tfBoolValue(plan.FailOnJobFailure)
	ctx = tflog.SetField(ctx, "skip_inventory_validation", skipInventoryValidation)
	ctx = tflog.SetField(ctx, "fail_on_job_failure", failOnJobFailure)
	tflog.Info(ctx, "Create called on certificate deployment resource")

	//Read cert from Keyfactor Command
	args := &api.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certificateIdInt,
	}
	certificateData, err := kfClient.GetCertificateContext(args)
	if err != nil {
		response.Diagnostics.AddError(
			"Deployment read error.",
			fmt.Sprintf(
				"Unknown error during read status of deployment of certificate '%v' to store '%s (%s)': "+err.Error(),
				certificateId,
				storeId,
				certificateAlias,
			),
		)
	}

	//sans := plan.SANs
	//metadata := plan.Metadata.Elems
	//vErr := validateCertificatesInStore(ctx, kfClient, certificateIdInt, storeId, 1) // Initial check to see if the cert is already deployed
	vErr := validateDeployment(
		ctx,
		kfClient,
		storeId,
		certificateAlias,
		certificateData,
		1,
	) // Initial check to see if the cert is already deployed
	if vErr == nil {
		response.Diagnostics.AddWarning(
			"Duplicate deployment.",
			fmt.Sprintf("Certificate '%v' is already deployed to '%s (%s)'", certificateId, storeId, certificateAlias),
		)
	} else {
		jobIDs, addErr := addCertificateToStore(
			ctx,
			kfClient,
			jobParams,
			&plan,
		)
		if addErr != nil {
			response.Diagnostics.AddError(
				"Certificate deployment error",
				fmt.Sprintf(
					"Unknown error during deploy of certificate '%v'(%s) to store '%s': "+addErr.Error(),
					certificateId,
					certificateAlias,
					storeId,
				),
			)
		}
		if response.Diagnostics.HasError() {
			return
		}

		// Check whether the store has an inventory schedule. If not, warn and skip the
		// validation poll: the orchestrator cannot confirm deployment without running inventory,
		// and we cannot reliably schedule inventory after the add job without a race condition
		// (the Immediate flag may be consumed before the management job completes). The
		// deployment job has been submitted; configure an inventory schedule on the store in
		// Command to enable future validation. The check is skipped entirely when the user
		// opted out of inventory validation, and the warning is replaced by job-status
		// validation when fail_on_job_failure is set.
		doInventoryValidation := false
		if !skipInventoryValidation {
			hasInventorySchedule, storeReadErr := storeHasInventorySchedule(kfClient, storeId)
			if storeReadErr != nil {
				tflog.Warn(ctx, fmt.Sprintf("Could not read store %s to check inventory schedule: %s", storeId, storeReadErr.Error()))
			}

			if hasInventorySchedule {
				doInventoryValidation = true
			} else if failOnJobFailure {
				if storeReadErr != nil {
					tflog.Info(ctx, fmt.Sprintf("Store read failed (%s); falling back to job-status-only validation.", storeReadErr.Error()))
				} else {
					tflog.Info(ctx, "Store has no inventory schedule; falling back to job-status-only validation.")
				}
			} else {
				response.Diagnostics.AddWarning(
					"Deployment submitted without inventory schedule.",
					fmt.Sprintf(
						"Certificate '%v' has been submitted for deployment to store '%s' (alias: '%s'), but the store "+
							"has no inventory schedule configured. Deployment cannot be validated until the orchestrator "+
							"runs inventory. Configure a daily or immediate inventory schedule on the store in Keyfactor "+
							"Command to enable deployment validation on future applies.",
						certificateId, storeId, certificateAlias,
					),
				)
			}
		} else {
			tflog.Info(ctx, "'skip_inventory_validation' is set; skipping deployment inventory validation.")
		}

		if failOnJobFailure {
			var inventoryCheck func() (bool, error)
			if doInventoryValidation {
				inventoryCheck = func() (bool, error) {
					return deploymentPresentInInventory(ctx, kfClient, storeId, certificateAlias, certificateData)
				}
			}
			waitDiags := waitForJobsAndInventory(ctx, r.p.sdkClient, deploymentJobWatch{
				jobIDs:         jobIDs,
				inventoryCheck: inventoryCheck,
				operation:      fmt.Sprintf("deployment of certificate '%v' to store '%s (%s)'", certificateId, storeId, certificateAlias),
			})
			response.Diagnostics.Append(waitDiags...)
			if response.Diagnostics.HasError() {
				// The Add job was already submitted to Keyfactor Command before this
				// wait began (T2): persist state now so a failed wait (an
				// orchestrator job failure, or e.g. the permission error from
				// getLatestJobHistoryEntry) leaves a tainted resource in state
				// instead of nothing at all. Without this, a mis-permissioned
				// identity resubmits a brand new management job on every
				// subsequent apply with nothing ever recorded in state. Note
				// this does not fully resolve the permission case: destroying
				// this tainted resource still requires the same Agent
				// Management - Read permission, since Delete submits its own
				// Remove job and polls its status the same way.
				stateDiags := response.State.Set(ctx, result)
				response.Diagnostics.Append(stateDiags...)
				return
			}
		} else if doInventoryValidation {
			//vErr2 := validateCertificatesInStore(ctx, kfClient, certificateIdInt, storeId, 100000)
			vErr2 := validateDeployment(
				ctx,
				kfClient,
				storeId,
				certificateAlias,
				certificateData,
				1000000,
			)
			if vErr2 != nil {
				response.Diagnostics.AddError(
					"Deployment validation error.",
					fmt.Sprintf(
						"Unknown error during validation of deploy of certificate '%v' to store '%s (%s)': "+vErr2.Error(),
						certificateId,
						storeId,
						certificateAlias,
					),
				)
			}
		}
		if response.Diagnostics.HasError() {
			return
		}
	}

	// Set state
	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

}

func (r resourceCommandCertificateDeployment) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	var state CommandCertificateDeployment
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	kfClient := r.p.client

	certificateId := state.CertificateId.Value
	certificateIdInt := int(certificateId)
	storeId := state.StoreId.Value
	//storeIdInt := int(storeId)
	certificateAlias := state.CertificateAlias.Value
	//keyPassword := state.KeyPassword.Value
	//hid := fmt.Sprintf("%s-%s-%s", certificateId, storeId, certificateAlias)

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	tflog.Info(ctx, "Create called on certificate deployment resource")

	// Get certificate context
	args := &api.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certificateIdInt,
	}
	certificateData, err := kfClient.GetCertificateContext(args)
	if err != nil {
		response.Diagnostics.AddError(
			"Deployment read error.",
			fmt.Sprintf(
				"Unknown error during read status of deployment of certificate '%s' to store '%s (%s)': "+err.Error(),
				certificateId,
				storeId,
				certificateAlias,
			),
		)
	}
	locations := certificateData.Locations
	for _, location := range locations {
		tflog.Debug(ctx, fmt.Sprintf("Certificate %v stored in location: %v", certificateIdInt, location))
	}

	// Set state
	var result = CommandCertificateDeployment{
		ID:               state.ID,
		CertificateId:    state.CertificateId,
		StoreId:          state.StoreId,
		CertificateAlias: state.CertificateAlias,
		KeyPassword:      state.KeyPassword,
		JobParameters:    state.JobParameters,
		Redeploy:         state.Redeploy,
		Overwrite:        state.Overwrite,
		SkipRemoval:      state.SkipRemoval,

		SkipInventoryValidation: state.SkipInventoryValidation,
		FailOnJobFailure:        state.FailOnJobFailure,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCommandCertificateDeployment) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	// Retrieve values from plan
	var plan CommandCertificateDeployment
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state CommandCertificateDeployment
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	certificateId := plan.CertificateId.Value
	certificateIdInt := int(certificateId)
	storeId := plan.StoreId.Value
	certificateAlias := plan.CertificateAlias.Value
	//keyPassword := plan.KeyPassword.Value

	overwrite := plan.Overwrite.Value
	forceRedploy := plan.Redeploy.Value

	var jobParams map[string]string
	_ = plan.JobParameters.ElementsAs(ctx, &jobParams, false)
	hid := fmt.Sprintf("%v-%s-%s", certificateId, storeId, certificateAlias)

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	//ctx = tflog.SetField(ctx, "key_password", keyPassword)
	ctx = tflog.SetField(ctx, "overwrite", overwrite)
	ctx = tflog.SetField(ctx, "redeploy", forceRedploy)
	skipInventoryValidation := tfBoolValue(plan.SkipInventoryValidation)
	failOnJobFailure := tfBoolValue(plan.FailOnJobFailure)
	ctx = tflog.SetField(ctx, "skip_inventory_validation", skipInventoryValidation)
	ctx = tflog.SetField(ctx, "fail_on_job_failure", failOnJobFailure)
	tflog.Info(ctx, "Update called on certificate deployment resource")

	//Read cert from Keyfactor Command
	args := &api.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certificateIdInt,
	}
	certificateData, err := kfClient.GetCertificateContext(args)
	if err != nil {
		response.Diagnostics.AddError(
			"Deployment read error.",
			fmt.Sprintf(
				"Unknown error during read status of deployment of certificate '%d' to store '%s (%s)': "+err.Error(),
				certificateId,
				storeId,
				certificateAlias,
			),
		)
	}

	vErr := validateDeployment(
		ctx,
		kfClient,
		storeId,
		certificateAlias,
		certificateData,
		1,
	) // Initial check to see if the cert is already deployed

	if vErr != nil {
		jobIDs, addErr := addCertificateToStore(
			ctx,
			kfClient,
			jobParams,
			&plan,
		)
		if addErr != nil {
			response.Diagnostics.AddError(
				"Certificate deployment error",
				fmt.Sprintf(
					"Unknown error during deploy of certificate '%v'(%s) to store '%s': "+addErr.Error(),
					certificateId,
					certificateAlias,
					storeId,
				),
			)
		}

		if response.Diagnostics.HasError() {
			return
		}

		if failOnJobFailure {
			var inventoryCheck func() (bool, error)
			if !skipInventoryValidation {
				// Probe the store's inventory schedule before committing to an
				// inventory-based wait: a schedule-less store never satisfies
				// deploymentPresentInInventory, which would otherwise poll
				// forever (T1). Fall back to job-status-only validation when no
				// schedule is present, matching Create's behavior.
				hasInventorySchedule, storeReadErr := storeHasInventorySchedule(kfClient, storeId)
				if storeReadErr != nil {
					tflog.Warn(ctx, fmt.Sprintf("Could not read store %s to check inventory schedule: %s", storeId, storeReadErr.Error()))
				}
				if storeReadErr != nil {
					tflog.Info(ctx, fmt.Sprintf("Store read failed (%s); falling back to job-status-only validation.", storeReadErr.Error()))
				} else if !hasInventorySchedule {
					tflog.Info(ctx, "Store has no inventory schedule; falling back to job-status-only validation.")
				} else {
					inventoryCheck = func() (bool, error) {
						return deploymentPresentInInventory(ctx, kfClient, storeId, certificateAlias, certificateData)
					}
				}
			}
			waitDiags := waitForJobsAndInventory(ctx, r.p.sdkClient, deploymentJobWatch{
				jobIDs:         jobIDs,
				inventoryCheck: inventoryCheck,
				operation:      fmt.Sprintf("deployment of certificate '%d' to store '%s (%s)'", certificateId, storeId, certificateAlias),
			})
			response.Diagnostics.Append(waitDiags...)
		} else if !skipInventoryValidation {
			vErr2 := validateDeployment(
				ctx,
				kfClient,
				storeId,
				certificateAlias,
				certificateData,
				1000000,
			) // Check if the cert is deployed
			if vErr2 != nil {
				response.Diagnostics.AddError(
					"Deployment validation error.",
					fmt.Sprintf(
						"Unknown error during validation of deploy of certificate '%d' to store '%s (%s)': "+vErr2.Error(),
						certificateId,
						storeId,
						certificateAlias,
					),
				)
			}
		} else {
			tflog.Info(ctx, "'skip_inventory_validation' is set; skipping deployment inventory validation.")
		}
	}

	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	var result = CommandCertificateDeployment{
		ID:               types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
		CertificateId:    plan.CertificateId,
		StoreId:          plan.StoreId,
		CertificateAlias: plan.CertificateAlias,
		KeyPassword:      plan.KeyPassword,
		JobParameters:    plan.JobParameters,
		Redeploy:         plan.Redeploy,
		Overwrite:        plan.Overwrite,
		SkipRemoval:      plan.SkipRemoval,

		SkipInventoryValidation: plan.SkipInventoryValidation,
		FailOnJobFailure:        plan.FailOnJobFailure,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCommandCertificateDeployment) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	var state CommandCertificateDeployment
	diags := request.State.Get(ctx, &state)

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Vars and logging contexts
	kfClient := r.p.client

	certificateId := state.CertificateId.Value
	//certificateIdInt := int(certificateId)
	storeId := state.StoreId.Value
	//storeIdInt := int(storeId)
	certificateAlias := state.CertificateAlias.Value
	//keyPassword := state.KeyPassword.Value
	//hid := fmt.Sprintf("%s-%s-%s", certificateId, storeId, certificateAlias)

	if certificateAlias == "" {
		// Look up the actual alias from the store inventory — the alias is the Name field in the inventory entry.
		// This handles store types (e.g. K8S TLS Secret) where the alias is not the thumbprint.
		inv, invErr := kfClient.GetCertStoreInventory(storeId)
		if invErr == nil && inv != nil {
			certIdInt := int(certificateId)
			for _, item := range *inv {
				for _, cert := range item.Certificates {
					if cert.Id == certIdInt {
						certificateAlias = item.Name
						break
					}
				}
				if certificateAlias != "" {
					break
				}
			}
		}
		if certificateAlias == "" {
			// Final fallback: use thumbprint
			lookupCertResp, lkErr := kfClient.GetCertificateContext(&api.GetCertificateContextArgs{Id: int(certificateId)})
			if lkErr != nil {
				response.Diagnostics.AddWarning(
					"Certificate removal error.",
					fmt.Sprintf("Error looking up certificate '%d' in Keyfactor: "+lkErr.Error(), certificateId),
				)
				response.State.RemoveResource(ctx)
				return
			}
			certificateAlias = lookupCertResp.Thumbprint
		}
	}
	skipInventoryValidation := tfBoolValue(state.SkipInventoryValidation)
	failOnJobFailure := tfBoolValue(state.FailOnJobFailure)

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	ctx = tflog.SetField(ctx, "skip_inventory_validation", skipInventoryValidation)
	ctx = tflog.SetField(ctx, "fail_on_job_failure", failOnJobFailure)
	tflog.Info(ctx, "Delete called on certificate deployment resource")

	// Remove certificate from store
	var diff []api.CertificateStore
	certStoreRequest := api.CertificateStore{
		CertificateStoreId: storeId,
		Alias:              certificateAlias,
	}
	diff = append(diff, certStoreRequest)

	// Remove resource from state
	//convert int64 to int
	certId := int(certificateId)

	if !state.SkipRemoval.Null && state.SkipRemoval.Value {
		tflog.Info(ctx, "Skipping removal of certificate from store 'skip_removal' set to `true`.")
		response.State.RemoveResource(ctx)
		return
	}

	tflog.Info(ctx, "Removing certificate from store.")
	jobIDs, certificateData, err := removeCertificateAliasFromStore(kfClient, &diff, certId)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			response.Diagnostics.AddWarning(
				"Certificate deployment not found.",
				fmt.Sprintf(
					"Certificate deployment '%v' to store '%s (%s)' not found, removing from state.",
					certificateId,
					storeId,
					certificateAlias,
				),
			)
			response.State.RemoveResource(ctx)
			return
		}
		response.Diagnostics.AddError(
			"Certificate deployment error",
			fmt.Sprintf(
				"Unknown error during removal of certificate '%d' from store '%s (%s)': "+err.Error(),
				certificateId,
				storeId,
				certificateAlias,
			),
		)
		return
	}

	if failOnJobFailure {
		var inventoryCheck func() (bool, error)
		if !skipInventoryValidation {
			// Probe the store's inventory schedule before committing to an
			// inventory-based wait (T1): the diff store is always the single
			// element built from storeId above.
			hasInventorySchedule, storeReadErr := storeHasInventorySchedule(kfClient, storeId)
			if storeReadErr != nil {
				tflog.Warn(ctx, fmt.Sprintf("Could not read store %s to check inventory schedule: %s", storeId, storeReadErr.Error()))
			}
			if storeReadErr != nil {
				tflog.Info(ctx, fmt.Sprintf("Store read failed (%s); falling back to job-status-only validation.", storeReadErr.Error()))
			} else if !hasInventorySchedule {
				tflog.Info(ctx, "Store has no inventory schedule; falling back to job-status-only validation.")
			} else {
				inventoryCheck = func() (bool, error) {
					for _, store := range diff {
						stillPresent, invErr := undeploymentStillPresent(ctx, kfClient, store.CertificateStoreId, certificateAlias, certificateData)
						if invErr != nil {
							return false, invErr
						}
						if stillPresent {
							return false, nil
						}
					}
					return true, nil
				}
			}
		}
		waitDiags := waitForJobsAndInventory(ctx, r.p.sdkClient, deploymentJobWatch{
			jobIDs:         jobIDs,
			inventoryCheck: inventoryCheck,
			operation:      fmt.Sprintf("removal of certificate '%d' from store '%s (%s)'", certificateId, storeId, certificateAlias),
		})
		response.Diagnostics.Append(waitDiags...)
	} else if !skipInventoryValidation {
		for _, store := range diff {
			validateErr := validateUndeployment(
				ctx,
				kfClient,
				store.CertificateStoreId,
				certId,
				certificateAlias,
				certificateData,
				100000,
			)
			if validateErr != nil {
				response.Diagnostics.AddError(
					"Certificate deployment error",
					fmt.Sprintf(
						"Unknown error during removal of certificate '%d' from store '%s (%s)': "+validateErr.Error(),
						certificateId,
						storeId,
						certificateAlias,
					),
				)
				break
			}
		}
	} else {
		tflog.Info(ctx, "'skip_inventory_validation' is set; skipping undeployment inventory validation.")
	}

	if response.Diagnostics.HasError() {
		return
	}
	response.State.RemoveResource(ctx)
}

func (r resourceCommandCertificateDeployment) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Error(ctx, "Import called on certificate deployment resource")
	response.Diagnostics.AddError(
		"Certificate deployment imports not implemented.",
		fmt.Sprintf("Error, only create and delete actions are supported for certificate deployments."),
	)
	if response.Diagnostics.HasError() {
		return
	}
}

// addCertificateToStore adds certificate certId to each of the stores configured by stores. Note that stores is a list of
// map[string]interface{} and contains the required configuration for api.AddCertificateToStores().
// It returns the orchestrator job IDs created by Keyfactor Command for the management job(s).
func addCertificateToStore(
	ctx context.Context,
	conn *api.Client,
	jobParams map[string]string,
	plan *CommandCertificateDeployment,
) ([]string, error) {
	var storesStruct []api.CertificateStore

	certificateIdInt := int(plan.CertificateId.Value)
	implicitOverwrite := plan.Overwrite.Value
	ctx = tflog.SetField(ctx, "certificate_id", certificateIdInt)
	ctx = tflog.SetField(ctx, "implicit_overwrite", implicitOverwrite)
	ctx = tflog.SetField(ctx, "certificate_alias", plan.CertificateAlias.Value)
	ctx = tflog.SetField(ctx, "store_id", plan.StoreId.Value)

	tflog.Debug(ctx, "Adding certificate to Keyfactor store")
	certificateStoreRequest := &api.CertificateStore{
		CertificateStoreId: plan.StoreId.Value,
		Alias:              plan.CertificateAlias.Value,
		IncludePrivateKey:  true, // TODO: Make this configurable
		Overwrite:          implicitOverwrite,
		PfxPassword:        plan.KeyPassword.Value,
		JobParameters:      jobParams,
	}
	storesStruct = append(storesStruct, *certificateStoreRequest)

	// Prepare configuration
	config := &api.AddCertificateToStore{
		CertificateId:     certificateIdInt,
		CertificateStores: &storesStruct,
		InventorySchedule: &api.InventorySchedule{
			Immediate: boolToPointer(true),
		},
	}

	// Add certificate to store
	jobIDs, err := tryAddCertificateToStore(
		ctx,
		conn,
		config,
		certificateStoreRequest,
		implicitOverwrite,
		plan.CertificateId.Value,
		plan.StoreId.Value,
	)
	if err != nil {
		return nil, err
	}

	tflog.Debug(
		ctx,
		fmt.Sprintf(
			"Successfully added certificate %v to Keyfactor store %v",
			plan.CertificateId.Value,
			plan.StoreId.Value,
		),
	)
	return jobIDs, nil
}

// Extracted helper function to avoid duplication. Returns the orchestrator job
// IDs created by Keyfactor Command for the management job(s).
func tryAddCertificateToStore(
	ctx context.Context,
	conn *api.Client,
	config *api.AddCertificateToStore,
	certificateStoreRequest *api.CertificateStore,
	implicitOverwrite bool,
	certificateId interface{},
	storeId interface{},
) ([]string, error) {
	resp, err := conn.AddCertificateToStores(config)
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateStoreRequest.Alias)
	ctx = tflog.SetField(ctx, "implicit_overwrite", implicitOverwrite)

	if err == nil {
		tflog.Trace(ctx, fmt.Sprintf("Response from Keyfactor: %v", resp))
		return resp, nil // No error, exit early
	}

	// Some store types (e.g. K8S TLS Secret) require Overwrite=true when an alias is provided
	// but also require the alias to already exist in the Command inventory. For new stores with
	// empty inventory the first call fails with "does not exist in certificate store". Previously
	// the code retried with Overwrite=false, which caused a confusing secondary error
	// ("Overwrite must be true") for store types that mandate Overwrite=true. The retry is
	// removed: return the original, more informative error directly.

	tflog.Error(ctx, fmt.Sprintf("Error adding certificate %v to Keyfactor store %v: %v", certificateId, storeId, err))
	return nil, err
}

// undeploymentStillPresent performs a single inventory read and reports whether the
// certificate is still present in the store under the given alias. Matching semantics
// are shared with validateUndeployment.
func undeploymentStillPresent(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
) (bool, error) {
	inv, invErr := conn.GetCertStoreInventory(storeId)
	if invErr != nil {
		return false, invErr
	}
	// check if inv is empty or nil
	if inv == nil || len(*inv) == 0 {
		return false, nil
	}
	for _, cert := range *inv {
		if cert.Name == certAlias {
			// Iterate through Certificates in the store and check if the certificate we're looking for is there
			for _, iCert := range cert.Certificates {
				if iCert.Id == certObj.Id {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func validateUndeployment(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certificateId int,
	certAlias string,
	certObj *api.GetCertificateResponse,
	maxIterations int,
) error {
	deployed := false
	tflog.Debug(ctx, fmt.Sprintf("Validating Keyfactor Command store %v inventory has removed %s", storeId, certAlias))
	retryDelay := 2
	for i := 0; i < maxIterations; i++ {
		stillPresent, invErr := undeploymentStillPresent(ctx, conn, storeId, certAlias, certObj)
		if invErr != nil {
			return invErr
		}
		deployed = stillPresent
		if deployed {
			tflog.Debug(
				ctx,
				fmt.Sprintf(
					"Certificate '%s'(%v) found in Keyfactor Command store '%s'(%v). Retrying in %v seconds",
					certObj.Thumbprint,
					certObj.Id,
					certAlias,
					storeId,
					retryDelay,
				),
			)
			time.Sleep(time.Duration(retryDelay) * time.Second)
			retryDelay *= 2
			if retryDelay > MAX_WAIT_SECONDS {
				retryDelay = MAX_WAIT_SECONDS
			}
		} else {
			break
		}
	}
	if deployed {
		return fmt.Errorf(
			"unable to remove certificate '%s'(%s) from Keyfactor Command store %v",
			certObj.Thumbprint,
			certAlias,
			storeId,
		)
	}
	return nil
}

// deploymentPresentInInventory performs a single inventory read and reports whether the
// certificate is present in the store — matched by alias, or by leaf certificate ID when
// no alias is set. Matching semantics are shared with validateDeployment.
func deploymentPresentInInventory(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
) (bool, error) {
	inv, invErr := conn.GetCertStoreInventory(storeId)
	if invErr != nil {
		return false, invErr
	}
	// check if inv is empty or nil
	if inv == nil || len(*inv) == 0 {
		return false, nil
	}
	for _, cert := range *inv {
		if cert.Name == certAlias {
			// Iterate through Certificates in the store and check if the certificate we're looking for is there
			for _, iCert := range cert.Certificates {
				if iCert.Id == certObj.Id {
					return true, nil
				}
			}
		} else if certAlias == "" {
			// if not alias is provided then just compare cert ID of the leaf node
			if len(cert.Ids) > 0 && cert.Ids[0] == certObj.Id { //TODO: This may not be the best way to do this as a cert ID can show up multiple times in a store
				return true, nil
			}
		}
	}
	return false, nil
}

func validateDeployment(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
	maxIterations int,
) error {
	valid := false
	tflog.Debug(
		ctx,
		fmt.Sprintf("Validating Keyfactor Command store %v inventory has been updated with %s", storeId, certAlias),
	)
	retryDelay := 2
	for i := 0; i < maxIterations; i++ {
		present, invErr := deploymentPresentInInventory(ctx, conn, storeId, certAlias, certObj)
		if invErr != nil {
			return invErr
		}
		valid = present
		if !valid {
			tflog.Debug(
				ctx,
				fmt.Sprintf(
					"Certificate %s not found in Keyfactor store %v. Retrying in %v seconds",
					certAlias,
					storeId,
					retryDelay,
				),
			)
			time.Sleep(time.Duration(retryDelay) * time.Second)
			retryDelay = retryDelay * 2
			if retryDelay > 60 {
				retryDelay = 60
			}
		} else {
			break
		}
	}
	if !valid {
		return fmt.Errorf("certificate %s not found in Keyfactor store %v", certAlias, storeId)
	}
	return nil
}

func validateCertificatesInStore(
	ctx context.Context,
	conn *api.Client,
	certificateId int,
	storeId string,
	maxIterations int,
) error {
	valid := false
	tflog.Debug(ctx, fmt.Sprintf("Validating certificate %v is in Keyfactor store %v", certificateId, storeId))
	retryDelay := 2
	for i := 0; i < maxIterations; i++ {
		args := &api.GetCertificateContextArgs{
			IncludeLocations: boolToPointer(true),
			Id:               certificateId,
		}
		certificateData, err := conn.GetCertificateContext(args)
		if err != nil {
			return err
		}

		certLocs := certificateData.Locations
		for _, loc := range certLocs {
			if loc.CertStoreId == storeId {
				valid = true
				i = maxIterations + 1 //break outer loop
				break
			}
		}

		//if len(findStringDifference(certificateStores, storeList)) == 0 && len(findStringDifference(storeList, certificateStores)) == 0 {
		//	valid = true
		//	break
		//}
		if !valid && i+1 < maxIterations {
			retryDelay = retryDelay * (i + 1)
			if retryDelay > 30 {
				retryDelay = 30
			}
			tflog.Debug(
				ctx,
				fmt.Sprintf(
					"Certificate %v not found in Keyfactor store %v. Retrying in %v seconds",
					certificateId,
					storeId,
					retryDelay,
				),
			)
			time.Sleep(time.Duration(retryDelay) * time.Second)
		}
	}
	if !valid {
		return fmt.Errorf("validateCertificatesInStore timed out. certificate could deploy eventually, but terraform change operation will fail. run terraform plan later to verify that the certificate was deployed successfully")
	}
	return nil
}

// removeCertificateAliasFromStore schedules a job to remove certId from each of the given
// stores. It returns the orchestrator job IDs created by Keyfactor Command along with the
// certificate context, which callers use for undeployment validation.
func removeCertificateAliasFromStore(
	conn *api.Client,
	certificateStores *[]api.CertificateStore,
	certId int,
) ([]string, *api.GetCertificateResponse, error) {
	// We want Keyfactor to immediately apply these changes.
	schedule := &api.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &api.RemoveCertificateFromStore{
		CertificateStores: certificateStores,
		InventorySchedule: schedule,
	}

	args := &api.GetCertificateContextArgs{
		IncludeLocations: boolToPointer(true),
		Id:               certId,
	}
	certificateData, cerErr := conn.GetCertificateContext(args)
	if cerErr != nil {
		return nil, nil, cerErr
	}

	jobIDs, err := conn.RemoveCertificateFromStores(config)
	if err != nil {
		return nil, certificateData, err
	}

	return jobIDs, certificateData, nil
}

// deploymentJobWatch describes what waitForJobsAndInventory should wait on after a
// management job has been submitted, per the resource's skip_inventory_validation and
// fail_on_job_failure attributes.
type deploymentJobWatch struct {
	// jobIDs are the orchestrator job IDs returned by the Add/Remove endpoints.
	jobIDs []string
	// inventoryCheck returns true once the store inventory reflects the desired
	// outcome. nil disables inventory polling (skip_inventory_validation), in which
	// case success is reached when every tracked job completes without failure.
	inventoryCheck func() (bool, error)
	// operation is a human-readable description used in diagnostics, e.g.
	// "deployment of certificate '123' to store 'abc (alias)'".
	operation string
}

// jobWatchOutcome is the interpreted state of an orchestrator job's latest history entry.
type jobWatchOutcome struct {
	terminal  bool
	failed    bool
	warning   bool
	willRetry bool
	message   string
}

// getLatestJobHistoryEntry queries GET /OrchestratorJobs/JobHistory for the given job ID
// and returns the entry with the highest JobHistoryId (the latest attempt), or nil when
// the job has not produced any history yet (not picked up by an orchestrator). The
// request sorts descending by JobHistoryId and caps the page at jobHistoryReturnLimit
// so the latest attempt is deterministically on the first (only) page returned; the
// client-side max-JobHistoryId scan below is kept as a belt-and-suspenders check (T4).
func getLatestJobHistoryEntry(
	ctx context.Context,
	sdkClient *keyfactor.APIClient,
	jobID string,
) (*v1.CertificateStoresJobHistoryResponse, error) {
	if sdkClient == nil || sdkClient.V1 == nil {
		return nil, fmt.Errorf("keyfactor SDK client is not configured")
	}
	entries, httpResp, err := sdkClient.V1.OrchestratorJobApi.NewGetOrchestratorJobsJobHistoryRequest(ctx).
		QueryString(fmt.Sprintf(`JobId -eq "%s"`, jobID)).
		SortField("JobHistoryId").
		SortAscending(v1.KEYFACTORCOMMONQUERYABLEEXTENSIONSSORTORDER__1). // 1 = descending
		ReturnLimit(jobHistoryReturnLimit).
		Execute()
	if err != nil {
		if httpResp != nil && (httpResp.StatusCode == http.StatusUnauthorized || httpResp.StatusCode == http.StatusForbidden) {
			return nil, fmt.Errorf(
				"HTTP %d from GET /OrchestratorJobs/JobHistory: the authenticated identity requires the "+
					"Agent Management - Read permission (claim /agents/management/read/) in Keyfactor Command to "+
					"watch orchestrator job status; grant the permission or unset 'fail_on_job_failure' (%s)",
				httpResp.StatusCode, err.Error(),
			)
		}
		return nil, err
	}
	var latest *v1.CertificateStoresJobHistoryResponse
	for i := range entries {
		e := &entries[i]
		if latest == nil || (e.JobHistoryId != nil && (latest.JobHistoryId == nil || *e.JobHistoryId > *latest.JobHistoryId)) {
			latest = e
		}
	}
	return latest, nil
}

// evaluateJobHistoryEntry interprets a job history entry per the Result/Status code
// mappings documented on the orchJob* constants. Completed and Acknowledged are both
// terminal statuses (the job will not run again); a terminal status with an Unknown
// result is treated as terminal-without-failure. CompletedWillRetry is not terminal:
// Keyfactor Command will run the job again.
func evaluateJobHistoryEntry(entry *v1.CertificateStoresJobHistoryResponse) jobWatchOutcome {
	if entry == nil {
		return jobWatchOutcome{}
	}
	var outcome jobWatchOutcome
	if m := entry.Message.Get(); m != nil {
		outcome.message = *m
	}
	if entry.Status == nil {
		return outcome
	}
	switch int32(*entry.Status) {
	case orchJobStatusCompleted, orchJobStatusAcknowledged:
		outcome.terminal = true
		if entry.Result != nil {
			switch int32(*entry.Result) {
			case orchJobResultFailure:
				outcome.failed = true
			case orchJobResultWarning:
				outcome.warning = true
			case orchJobResultSuccess:
				// Explicit no-op: success is the terminal state absent a
				// failure or warning result above.
			}
		}
	case orchJobStatusCompletedWillRetry:
		outcome.willRetry = true
	}
	return outcome
}

// waitForJobsAndInventory implements the wait behavior for fail_on_job_failure. Each
// iteration checks the latest job history of every still-pending orchestrator job — a
// terminal failure fails the operation immediately with the orchestrator's message —
// and then, when inventory validation is active, performs a single inventory check
// whose success ends the wait. When inventory validation is skipped, the wait ends
// once every tracked job has completed without failure. Like the inventory-only
// validation loops, this waits indefinitely on jobs that never complete.
func waitForJobsAndInventory(
	ctx context.Context,
	sdkClient *keyfactor.APIClient,
	watch deploymentJobWatch,
) diag.Diagnostics {
	var diags diag.Diagnostics

	pending := make(map[string]bool, len(watch.jobIDs))
	for _, id := range watch.jobIDs {
		pending[id] = true
	}
	if len(pending) == 0 {
		diags.AddWarning(
			"No orchestrator jobs to watch.",
			fmt.Sprintf(
				"Keyfactor Command returned no job IDs for the %s, so 'fail_on_job_failure' cannot watch the job status.",
				watch.operation,
			),
		)
		if watch.inventoryCheck == nil {
			return diags
		}
	}

	retryDelay := 2
	for {
		for jobID := range pending {
			entry, jhErr := getLatestJobHistoryEntry(ctx, sdkClient, jobID)
			if jhErr != nil {
				diags.AddError(
					"Orchestrator job status error.",
					fmt.Sprintf(
						"Error checking the status of orchestrator job '%s' for the %s: %s",
						jobID, watch.operation, jhErr.Error(),
					),
				)
				return diags
			}
			outcome := evaluateJobHistoryEntry(entry)
			switch {
			case outcome.failed:
				msg := outcome.message
				if msg == "" {
					msg = "(no failure message reported by the orchestrator)"
				}
				diags.AddError(
					"Orchestrator job failed.",
					fmt.Sprintf(
						"Orchestrator job '%s' for the %s completed with a failure result: %s",
						jobID, watch.operation, msg,
					),
				)
				return diags
			case outcome.terminal:
				if outcome.warning {
					diags.AddWarning(
						"Orchestrator job completed with warnings.",
						fmt.Sprintf(
							"Orchestrator job '%s' for the %s completed with a warning result: %s",
							jobID, watch.operation, outcome.message,
						),
					)
				}
				delete(pending, jobID)
			case outcome.willRetry:
				tflog.Warn(ctx, fmt.Sprintf(
					"Orchestrator job %s attempt failed and will be retried by Keyfactor Command: %s",
					jobID, outcome.message,
				))
			default:
				tflog.Debug(ctx, fmt.Sprintf("Orchestrator job %s has not completed yet", jobID))
			}
		}

		if watch.inventoryCheck != nil {
			done, invErr := watch.inventoryCheck()
			if invErr != nil {
				diags.AddError(
					"Deployment validation error.",
					fmt.Sprintf("Unknown error during validation of the %s: %s", watch.operation, invErr.Error()),
				)
				return diags
			}
			if done {
				return diags
			}
		} else if len(pending) == 0 {
			// Job status is the only success signal when inventory validation is skipped.
			return diags
		}

		time.Sleep(time.Duration(retryDelay) * time.Second)
		retryDelay *= 2
		if retryDelay > 60 {
			retryDelay = 60
		}
	}
}
