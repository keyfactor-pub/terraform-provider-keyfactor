package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// storeHasInventorySchedule reports whether the certificate store storeId has any
// inventory schedule configured (Immediate, Interval, Daily, or ExactlyOnce). When
// the store read itself fails, readErr is returned and hasSchedule is always false :
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
				Type:        types.Int64Type,
				Required:    true,
				Description: "Keyfactor certificate ID",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					// deploymentOverwriteOnCertIDChange replaces the bare
					// tfsdk.RequiresReplace(): it still forces replacement when
					// overwrite is not true, but allows the Update path when the
					// operator has explicitly set overwrite = true.
					deploymentOverwriteOnCertIDChange{},
				},
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
			"max_inventory_wait": {
				Type:     types.Int64Type,
				Optional: true,
				Description: "Maximum seconds to wait for inventory confirmation after deployment. " +
					"Null (default) waits indefinitely (current behavior). " +
					"0 skips inventory verification entirely (fire-and-forget). " +
					"Values greater than 0 wait up to that many seconds, then proceed with a warning if not confirmed.",
				Validators: []tfsdk.AttributeValidator{
					int64AtLeastValidator{min: 0},
				},
			},
		},
		Description: "Used to schedule a certificate deployment(" +
			"/management) job on Keyfactor Command using the `/OrchestratorJobs/Custom` API to deploy certificates to" +
			" `keyfactor_certificate_store` resources. " +
			"*NOTE:* The jobs are run asynchronously, and depend on orchestrator agent check in schedules. The provider will wait for the job to complete successfully and may run for a long time.",
		MarkdownDescription: `
Used to schedule a certificate deployment(/management) job on Keyfactor Command using the "/OrchestratorJobs/Custom"
API to deploy certificates to "keyfactor_certificate_store" resources.

!> **Warning:** Orchestrator agent jobs are run asynchronously outside of Terraform, and depend on orchestrator agent check in schedules. A "keyfactor_certificate_deployment" *will not finish* successfully until the destination certificate store's certificate inventory has been updated to include the deployed certificate.
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
	// duplicate-deployment branching below, and reused for the end-of-Create
	// state set (U2).
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
		MaxInventoryWait: plan.MaxInventoryWait,
	}

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
	//ctx = tflog.SetField(ctx, "key_password", keyPassword)
	ctx = tflog.SetField(ctx, "overwrite", overwrite)
	ctx = tflog.SetField(ctx, "redeploy", forceRedploy)
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
				"Unknown error during read status of deployment of certificate '%v' to store '%s (%s)': ",
				certificateId,
				storeId,
				certificateAlias,
			)+err.Error(),
		)
		return
	}

	alreadyDeployed, preCheckErr := pollInventory(
		ctx,
		kfClient,
		storeId,
		certificateAlias,
		certificateData,
		true, // wantPresent: looking for the cert
		1,    // single-shot pre-check
		nil,  // no deadline
	)
	if preCheckErr != nil {
		response.Diagnostics.AddError(
			"Deployment pre-check error.",
			fmt.Sprintf(
				"Error checking existing deployment of certificate '%v' to store '%s (%s)': ",
				certificateId,
				storeId,
				certificateAlias,
			)+preCheckErr.Error(),
		)
		return
	}
	if alreadyDeployed {
		response.Diagnostics.AddWarning(
			"Duplicate deployment.",
			fmt.Sprintf("Certificate '%v' is already deployed to '%s (%s)'", certificateId, storeId, certificateAlias),
		)
	} else {
		addErr := addCertificateToStore(
			ctx,
			kfClient,
			jobParams,
			&plan,
		)
		if addErr != nil {
			response.Diagnostics.AddError(
				"Certificate deployment error",
				fmt.Sprintf(
					"Unknown error during deploy of certificate '%v'(%s) to store '%s': ",
					certificateId,
					certificateAlias,
					storeId,
				)+addErr.Error(),
			)
		}
		if response.Diagnostics.HasError() {
			return
		}

		waitForInventory(ctx, &response.Diagnostics, kfClient, plan.MaxInventoryWait, storeId, certificateAlias, certificateData, certificateIdInt, false)
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
				"Unknown error during read status of deployment of certificate '%d' to store '%s (%s)': ",
				certificateId,
				storeId,
				certificateAlias,
			)+err.Error(),
		)
	}
	locations := certificateData.Locations
	for _, location := range locations {
		tflog.Debug(ctx, fmt.Sprintf("Certificate %v stored in location: %v", certificateIdInt, location))
	}

	// Set state. This deployment resource has no server-refreshable fields of
	// its own (the certificate/store/alias identity and write-only knobs are
	// all sourced from state) -- the GetCertificateContext call above exists
	// to confirm the certificate itself is still reachable, not to refresh
	// any field, so state is written back as-is.
	diags = response.State.Set(ctx, state)
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
				"Unknown error during read status of deployment of certificate '%d' to store '%s (%s)': ",
				certificateId,
				storeId,
				certificateAlias,
			)+err.Error(),
		)
		return
	}

	alreadyDeployed, preCheckErr := pollInventory(
		ctx,
		kfClient,
		storeId,
		certificateAlias,
		certificateData,
		true, // wantPresent: looking for the cert
		1,    // single-shot pre-check
		nil,  // no deadline
	)
	if preCheckErr != nil {
		response.Diagnostics.AddError(
			"Deployment pre-check error.",
			fmt.Sprintf(
				"Error checking existing deployment of certificate '%d' to store '%s (%s)': ",
				certificateId,
				storeId,
				certificateAlias,
			)+preCheckErr.Error(),
		)
		return
	}

	if !alreadyDeployed {
		addErr := addCertificateToStore(
			ctx,
			kfClient,
			jobParams,
			&plan,
		)
		if addErr != nil {
			response.Diagnostics.AddError(
				"Certificate deployment error",
				fmt.Sprintf(
					"Unknown error during deploy of certificate '%v'(%s) to store '%s': ",
					certificateId,
					certificateAlias,
					storeId,
				)+addErr.Error(),
			)
		}

		if response.Diagnostics.HasError() {
			return
		}

		waitForInventory(ctx, &response.Diagnostics, kfClient, plan.MaxInventoryWait, storeId, certificateAlias, certificateData, certificateIdInt, false)
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
		MaxInventoryWait: plan.MaxInventoryWait,
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
		// Look up the actual alias from the store inventory : the alias is the Name field in the inventory entry.
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
					fmt.Sprintf("Error looking up certificate '%d' in Keyfactor: ", certificateId)+lkErr.Error(),
				)
				response.State.RemoveResource(ctx)
				return
			}
			certificateAlias = lookupCertResp.Thumbprint
		}
	}

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
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
	certificateData, err := removeCertificateAliasFromStore(kfClient, &diff, certId)
	if err != nil {
		// This call site needs stricter not-found handling than the other
		// two isNotFoundError call sites in this codebase
		// (resource_keyfactor_security_role.go, resource_keyfactor_certificate_store_type.go):
		// those are simple single-resource GETs where "does not exist" is
		// unambiguous -- there is exactly one thing being read, so a
		// not-found error about it is safe to treat as "already gone."
		// Here, removeCertificateAliasFromStore's failure can instead be
		// about the STORE'S BACKING ORCHESTRATOR AGENT being gone (confirmed
		// live-Command message: "Agent with id of '<guid>' does not exist"),
		// which matches isNotFoundError's "does not exist" pattern just as
		// readily as a genuinely-gone deployment/store/alias/certificate
		// would -- but describes a completely different, higher-stakes
		// situation: the certificate is likely still physically deployed on
		// the target, with no agent left to run the removal job. Silently
		// dropping this resource from state in that case would make
		// Terraform believe the cert was cleanly removed when it was not --
		// an orphaned, untracked, still-deployed certificate/key. So an
		// agent-shaped not-found is deliberately NOT treated as safe here,
		// even though it is a "confirmed not found" by isNotFoundError's own
		// (correct, for its other callers) definition.
		if isNotFoundError(err) && !isAgentMissingNotFoundError(err) {
			ctx = tflog.SetField(ctx, "error", err.Error())
			tflog.Info(ctx, "Certificate deployment not found on Keyfactor Command, removing from state")
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
				"Unknown error during removal of certificate '%d' from store '%s (%s)': ",
				certificateId,
				storeId,
				certificateAlias,
			)+err.Error(),
		)
		return
	}

	waitForInventory(ctx, &response.Diagnostics, kfClient, state.MaxInventoryWait, storeId, certificateAlias, certificateData, certId, true)

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

// waitForInventory waits for inventory confirmation after a deployment or removal job has
// been submitted. It encapsulates the fire-and-forget check, inventory-schedule check,
// deadline computation, and the pollInventory poll, writing diagnostics directly into diags.
//
// isRemoval controls message wording and the direction of the pollInventory call
// (wantPresent=false for removal, wantPresent=true for deployment). certId is the integer
// Keyfactor certificate ID used in diagnostic messages.
func waitForInventory(
	ctx context.Context,
	diags *diag.Diagnostics,
	conn *api.Client,
	maxWait types.Int64,
	storeId string,
	certAlias string,
	certData *api.GetCertificateResponse,
	certId int,
	isRemoval bool,
) {
	action := "deployment"
	actionTitle := "Deployment"
	preposition := "to"
	if isRemoval {
		action = "removal"
		actionTitle = "Removal"
		preposition = "from"
	}

	// Fire-and-forget: max_inventory_wait = 0 → skip all validation.
	if !maxWait.Null && !maxWait.Unknown && maxWait.Value == 0 {
		diags.AddWarning(
			fmt.Sprintf("%s verification skipped.", actionTitle),
			fmt.Sprintf(
				"Certificate %d was submitted for %s %s store %s but inventory verification was skipped (max_inventory_wait = 0).",
				certId, action, preposition, storeId,
			),
		)
		return
	}

	// Check whether the store has an inventory schedule. If not, warn and skip the
	// validation poll: the orchestrator cannot confirm the operation without running
	// inventory, and we cannot reliably trigger inventory after the management job
	// without a race. Configure an inventory schedule on the store to enable future
	// validation.
	hasInventorySchedule, storeReadErr := storeHasInventorySchedule(conn, storeId)
	if storeReadErr != nil {
		tflog.Warn(ctx, fmt.Sprintf("Could not read store %s to check inventory schedule: %s", storeId, storeReadErr.Error()))
		diags.AddWarning(
			fmt.Sprintf("Certificate %s submitted — could not verify inventory schedule.", action),
			fmt.Sprintf(
				"Certificate %d has been submitted for %s to store '%s' (alias: '%s'), but the store's "+
					"inventory schedule could not be verified due to an API error: %s. "+
					"The provider will skip inventory validation for this apply.",
				certId, action, storeId, certAlias, storeReadErr.Error(),
			),
		)
		return
	}
	if !hasInventorySchedule {
		diags.AddWarning(
			fmt.Sprintf("Certificate %s submitted without inventory schedule.", action),
			fmt.Sprintf(
				"Certificate %d has been submitted for %s to store '%s' (alias: '%s'), but the store "+
					"has no inventory schedule configured. The %s cannot be validated until the orchestrator "+
					"runs inventory. Configure a daily or immediate inventory schedule on the store in Keyfactor "+
					"Command to enable validation on future applies.",
				certId, action, storeId, certAlias, action,
			),
		)
		return
	}

	// Compute deadline: null/unknown → indefinite (nil), >0 → bounded.
	var deadline *time.Time
	if !maxWait.Null && !maxWait.Unknown && maxWait.Value > 0 {
		t := time.Now().Add(time.Duration(maxWait.Value) * time.Second)
		deadline = &t
	}

	// Poll until confirmed, deadline reached, or error.
	confirmed, vErr := pollInventory(ctx, conn, storeId, certAlias, certData, !isRemoval, 1000000, deadline)

	if vErr != nil {
		diags.AddError(
			fmt.Sprintf("Certificate %s validation error.", action),
			fmt.Sprintf(
				"Unknown error during validation of %s of certificate %d to store '%s (%s)': ",
				action, certId, storeId, certAlias,
			)+vErr.Error(),
		)
		return
	}

	if !confirmed {
		if maxWait.Null || maxWait.Unknown {
			// Indefinite wait exhausted all iterations — hard failure (preserves old behavior).
			if isRemoval {
				diags.AddError(
					"Removal validation failed.",
					fmt.Sprintf(
						"Certificate %d was not removed from store %s inventory after exhausting all retry attempts.",
						certId, storeId,
					),
				)
			} else {
				diags.AddError(
					"Deployment validation failed.",
					fmt.Sprintf(
						"Certificate %d was not found in store %s inventory after exhausting all retry attempts.",
						certId, storeId,
					),
				)
			}
		} else {
			// User-defined timeout — warn, don't fail (user opted into this behavior).
			diags.AddWarning(
				fmt.Sprintf("%s verification timed out.", actionTitle),
				fmt.Sprintf(
					"Certificate %d was submitted for %s %s store %s but inventory confirmation was not received within %d seconds. The %s may still complete — run `terraform plan` to check.",
					certId, action, preposition, storeId, maxWait.Value, action,
				),
			)
		}
	}
}

// addCertificateToStore adds certificate certId to each of the stores configured by stores. Note that stores is a list of
// map[string]interface{} and contains the required configuration for api.AddCertificateToStores().
func addCertificateToStore(
	ctx context.Context,
	conn *api.Client,
	jobParams map[string]string,
	plan *CommandCertificateDeployment,
) error {
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
	err := tryAddCertificateToStore(
		ctx,
		conn,
		config,
		certificateStoreRequest,
		implicitOverwrite,
		plan.CertificateId.Value,
		plan.StoreId.Value,
	)
	if err != nil {
		return err
	}

	tflog.Debug(
		ctx,
		fmt.Sprintf(
			"Successfully added certificate %v to Keyfactor store %v",
			plan.CertificateId.Value,
			plan.StoreId.Value,
		),
	)
	return nil
}

// Extracted helper function to avoid duplication.
func tryAddCertificateToStore(
	ctx context.Context,
	conn *api.Client,
	config *api.AddCertificateToStore,
	certificateStoreRequest *api.CertificateStore,
	implicitOverwrite bool,
	certificateId interface{},
	storeId interface{},
) error {
	resp, err := conn.AddCertificateToStores(config)
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateStoreRequest.Alias)
	ctx = tflog.SetField(ctx, "implicit_overwrite", implicitOverwrite)

	if err == nil {
		tflog.Trace(ctx, fmt.Sprintf("Response from Keyfactor: %v", resp))
		return nil // No error, exit early
	}

	// Some store types (e.g. K8S TLS Secret) require Overwrite=true when an alias is provided
	// but also require the alias to already exist in the Command inventory. For new stores with
	// empty inventory the first call fails with "does not exist in certificate store". Previously
	// the code retried with Overwrite=false, which caused a confusing secondary error
	// ("Overwrite must be true") for store types that mandate Overwrite=true. The retry is
	// removed: return the original, more informative error directly.

	tflog.Error(ctx, fmt.Sprintf("Error adding certificate %v to Keyfactor store %v: %v", certificateId, storeId, err))
	return err
}

// certificateInInventory performs a single inventory read and reports whether certObj is
// present in the store under certAlias. It backs both undeploymentStillPresent and
// deploymentPresentInInventory, which differ only in matchEmptyAliasByLeafId: deployment
// checks also match by the leaf certificate's ID when no alias is set (certAlias == ""),
// while undeployment checks never fall back to ID-only matching for an empty alias.
func certificateInInventory(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
	matchEmptyAliasByLeafId bool,
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
		} else if matchEmptyAliasByLeafId && certAlias == "" {
			// if not alias is provided then just compare cert ID of the leaf node
			if len(cert.Ids) > 0 && cert.Ids[0] == certObj.Id { //TODO: This may not be the best way to do this as a cert ID can show up multiple times in a store
				return true, nil
			}
		}
	}
	return false, nil
}

// undeploymentStillPresent performs a single inventory read and reports whether the
// certificate is still present in the store under the given alias. Matching semantics
// are shared with pollInventory (wantPresent=false path).
func undeploymentStillPresent(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
) (bool, error) {
	return certificateInInventory(ctx, conn, storeId, certAlias, certObj, false)
}

// deploymentPresentInInventory performs a single inventory read and reports whether the
// certificate is present in the store: matched by alias, or by leaf certificate ID when
// no alias is set. Matching semantics are shared with pollInventory.
func deploymentPresentInInventory(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
) (bool, error) {
	return certificateInInventory(ctx, conn, storeId, certAlias, certObj, true)
}

// pollInventory polls the store inventory until the desired state is reached or the
// deadline/maxIterations is exhausted.
//
// When wantPresent is true (deploy path): polls until the certificate appears in inventory.
// When wantPresent is false (undeploy path): polls until the certificate is gone from inventory.
//
// Returns (true, nil) when the desired state is confirmed.
// Returns (false, nil) when the deadline or all iterations are exhausted without confirmation —
// callers should treat this as a timeout and emit a warning.
// Returns (false, err) if a context cancellation or inventory read error occurred.
func pollInventory(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
	wantPresent bool,
	maxIterations int,
	deadline *time.Time,
) (bool, error) {
	if wantPresent {
		tflog.Debug(ctx, fmt.Sprintf("Validating Keyfactor Command store %v inventory has been updated with %s", storeId, certAlias))
	} else {
		tflog.Debug(ctx, fmt.Sprintf("Validating Keyfactor Command store %v inventory has removed %s", storeId, certAlias))
	}
	retryDelay := 2
	for i := 0; i < maxIterations; i++ {
		if deadline != nil && time.Now().After(*deadline) {
			return false, nil // deadline reached
		}
		var present bool
		var invErr error
		if wantPresent {
			present, invErr = deploymentPresentInInventory(ctx, conn, storeId, certAlias, certObj)
		} else {
			present, invErr = undeploymentStillPresent(ctx, conn, storeId, certAlias, certObj)
		}
		if invErr != nil {
			return false, invErr
		}
		// Success condition: present matches wantPresent (deploy) or absent (!present) matches !wantPresent (undeploy).
		if present == wantPresent {
			return true, nil
		}
		// Skip sleep on the last iteration — there is no subsequent poll.
		if i == maxIterations-1 {
			break
		}
		if wantPresent {
			tflog.Debug(ctx, fmt.Sprintf("Certificate %s not found in Keyfactor store %v. Retrying in %v seconds", certAlias, storeId, retryDelay))
		} else {
			tflog.Debug(ctx, fmt.Sprintf(
				"Certificate '%s'(%v) found in Keyfactor Command store '%s'(%v). Retrying in %v seconds",
				certObj.Thumbprint, certObj.Id, certAlias, storeId, retryDelay,
			))
		}
		select {
		case <-time.After(time.Duration(retryDelay) * time.Second):
			// continue polling
		case <-ctx.Done():
			return false, ctx.Err()
		}
		retryDelay *= 2
		if retryDelay > 60 {
			retryDelay = 60
		}
	}
	return false, nil // all iterations exhausted
}

// removeCertificateAliasFromStore schedules a job to remove certId from each of the given
// stores. It returns the certificate context, which callers use for undeployment validation.
func removeCertificateAliasFromStore(
	conn *api.Client,
	certificateStores *[]api.CertificateStore,
	certId int,
) (*api.GetCertificateResponse, error) {
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
		return nil, cerErr
	}

	_, err := conn.RemoveCertificateFromStores(config)
	if err != nil {
		return certificateData, err
	}

	return certificateData, nil
}
