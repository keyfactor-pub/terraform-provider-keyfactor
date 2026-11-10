package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
	if d := req.State.GetAttribute(ctx, req.AttributePath, &oldID); d.HasError() {
		resp.Diagnostics.Append(d...)
		return
	}
	if d := req.Plan.GetAttribute(ctx, req.AttributePath, &newID); d.HasError() {
		resp.Diagnostics.Append(d...)
		return
	}

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
			"include_private_key": {
				Type:     types.BoolType,
				Optional: true,
				Description: "If `true` (the default), the private key is deployed to the store along with the certificate. " +
					"Set to `false` to deploy the certificate without its private key (e.g. for trust stores). " +
					"With `false`, the deployment is refused if an entry already exists under the target `certificate_alias` (for this or any other certificate), because an existing entry may carry a private key that cannot be stripped. " +
					"Changing this value replaces the deployment (the existing entry is removed, then re-added), because an " +
					"in-place overwrite cannot reliably strip an existing private key. It cannot be changed while " +
					"`skip_removal` is `true` in the current state (apply `skip_removal = false` first). Because the " +
					"replacement keeps the same certificate and alias, changing this value is not supported with " +
					"`lifecycle { create_before_destroy = true }`: the replace must delete the existing deployment first " +
					"(the default), see the resource description. The value must be known at plan time (use a literal or an input variable, not a " +
					"value computed during apply), unless the deployment is already being replaced for another reason, because it " +
					"decides whether the deployment is replaced. Removing the " +
					"attribute reverts to the default of `true`.",
			},
			"skip_removal": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "If set to `true`, deleting the resource will not remove the certificate from the store. Defaults to `false`.",
			},
		},
		Description: "Used to schedule a certificate deployment(" +
			"/management) job on Keyfactor Command using the `/OrchestratorJobs/Custom` API to deploy certificates to" +
			" `keyfactor_certificate_store` resources. " +
			"*NOTE:* The jobs are run asynchronously, and depend on orchestrator agent check in schedules. The provider will wait for the job to complete successfully and may run for a long time. " +
			"*NOTE:* `lifecycle { create_before_destroy = true }` is not supported for any replacement that keeps the same certificate and " +
			"alias in the same store (for example a change to `include_private_key`, `redeploy` or `key_password`): creating the replacement " +
			"adopts the existing store entry, and the old instance's delete then removes that entry, leaving the store without the certificate. " +
			"Use the default replacement order (destroy, then create) for this resource. " +
			"*NOTE:* `terraform apply -replace` (or `terraform taint`) on a deployment whose state has `skip_removal = true` and " +
			"`include_private_key = false` is not supported: Terraform plans it without consulting the provider, the delete step does " +
			"not remove the existing store entry, and the replacement's create step then refuses that entry because it may contain the " +
			"private key. Set `skip_removal = false` and apply it first. Replacements the provider can see in the plan (a change to " +
			"`certificate_id`, `certificate_store_id`, `certificate_alias`, `key_password`, `redeploy` or `include_private_key`) are " +
			"rejected at plan time in that situation.",
		MarkdownDescription: "\nUsed to schedule a certificate deployment(/management) job on Keyfactor Command using the `/OrchestratorJobs/Custom`\n" +
			"API to deploy certificates to `keyfactor_certificate_store` resources.\n\n" +
			"!> **Warning:** Orchestrator agent jobs are run asynchronously outside of Terraform, and depend on orchestrator agent check in schedules. A `keyfactor_certificate_deployment` *will not finish* successfully until the destination certificate store's certificate inventory has been updated to include the deployed certificate.\n\n" +
			"~> **Note:** `lifecycle { create_before_destroy = true }` is not supported for any replacement that keeps the same certificate and alias in the same store (for example a change to `include_private_key`, `redeploy` or `key_password`). Creating the replacement adopts the existing store entry, and the old instance's delete then removes that entry, leaving the store without the certificate. Use the default replacement order (destroy, then create) for this resource.\n\n" +
			"~> **Note:** `terraform apply -replace` (or `terraform taint`) on a deployment whose state has `skip_removal = true` and `include_private_key = false` is not supported: Terraform plans it without consulting the provider, the delete step does not remove the existing store entry, and the replacement's create step then refuses that entry because it may contain the private key. Set `skip_removal = false` and apply it first. Replacements the provider can see in the plan (a change to `certificate_id`, `certificate_store_id`, `certificate_alias`, `key_password`, `redeploy` or `include_private_key`) are rejected at plan time in that situation.\n",
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

	jobParams, jpDiags := jobParametersFromPlan(ctx, plan.JobParameters)
	response.Diagnostics.Append(jpDiags...)
	if response.Diagnostics.HasError() {
		return
	}
	hid := fmt.Sprintf("%v-%s-%s", certificateId, storeId, certificateAlias)

	// Built once here since every input (hid, plan.*) is available before the
	// duplicate-deployment branching below, and reused for the end-of-Create
	// state set (U2).
	result := CommandCertificateDeployment{
		ID:                types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
		CertificateId:     plan.CertificateId,
		StoreId:           plan.StoreId,
		CertificateAlias:  plan.CertificateAlias,
		KeyPassword:       plan.KeyPassword,
		JobParameters:     plan.JobParameters,
		Redeploy:          plan.Redeploy,
		Overwrite:         plan.Overwrite,
		SkipRemoval:       plan.SkipRemoval,
		IncludePrivateKey: plan.IncludePrivateKey,
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
		// certificateData is nil: nothing below can be decided without it.
		return
	}

	// Initial check to see if the cert is already deployed. This is a single inventory read,
	// not validateDeployment: an inventory READ error must not be mistaken for "not deployed",
	// otherwise we would submit a deployment job (possibly a duplicate or an overwrite) while
	// Command is unreachable.
	presence, presenceErr := deploymentInventoryPresence(kfClient, storeId, certificateAlias, certificateData)
	if presenceErr != nil {
		response.Diagnostics.AddError(
			"Deployment read error.",
			fmt.Sprintf(
				"Unable to read the inventory of store '%s' to check whether certificate '%v' (%s) is already deployed; "+
					"no deployment job was submitted: ",
				storeId,
				certificateId,
				certificateAlias,
			)+presenceErr.Error(),
		)
		return
	}
	alreadyDeployed := presence.CertificatePresent
	if alreadyDeployed && !includePrivateKeyOrDefault(plan.IncludePrivateKey) {
		// The certificate is already in the store and we cannot verify that the existing entry
		// has no private key. An in-place overwrite does not reliably strip it (e.g. K8S secrets
		// keep tls.key), so fail loudly instead of reporting a false success.
		summary, detail := existingEntryPrivateKeyDiagnostic(certificateId, storeId, certificateAlias)
		response.Diagnostics.AddError(summary, detail)
		return
	}
	if presence.AliasOccupied && !includePrivateKeyOrDefault(plan.IncludePrivateKey) {
		// The target alias is held by a different certificate. Deploying would overwrite that entry
		// without a private key, and what is left of its old key material depends on the store type
		// (lab evidence only covers K8S store types), so refuse rather than overwrite silently.
		summary, detail := occupiedAliasPrivateKeyDiagnostic(certificateId, storeId, certificateAlias)
		response.Diagnostics.AddError(summary, detail)
		return
	}
	if alreadyDeployed {
		response.Diagnostics.AddWarning(
			"Duplicate deployment.",
			fmt.Sprintf("Certificate '%v' is already deployed to '%s (%s)'", certificateId, storeId, certificateAlias),
		)
	} else {
		addErr := addCertificateToStore(ctx, kfClient, jobParams, &plan)
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

		// Check whether the store has an inventory schedule. If not, warn and skip the
		// validation poll: the orchestrator cannot confirm deployment without running inventory,
		// and we cannot reliably schedule inventory after the add job without a race condition
		// (the Immediate flag may be consumed before the management job completes). The
		// deployment job has been submitted; configure an inventory schedule on the store in
		// Command to enable future validation.
		hasInventorySchedule, storeReadErr := storeHasInventorySchedule(kfClient, storeId)
		if storeReadErr != nil {
			tflog.Warn(ctx, fmt.Sprintf("Could not read store %s to check inventory schedule: %s", storeId, storeReadErr.Error()))
		}

		if !hasInventorySchedule {
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
		} else {
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
						"Unknown error during validation of deploy of certificate '%v' to store '%s (%s)': ",
						certificateId,
						storeId,
						certificateAlias,
					)+vErr2.Error(),
				)
			}
			if response.Diagnostics.HasError() {
				return
			}
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
		// A certificate that no longer exists in Command cannot be deployed or tracked: drop the
		// deployment from state so the next plan shows it as missing (Create will then fail loudly
		// on the missing certificate rather than the resource silently vanishing), exactly as Delete
		// treats a confirmed-gone object. An agent-shaped "does not exist" is not a missing
		// certificate (see isAgentMissingNotFoundError), and any other failure (network, auth, 5xx)
		// says nothing about whether the deployment still exists, so both are reported as errors and
		// the prior state is left untouched.
		if isNotFoundError(err) && !isAgentMissingNotFoundError(err) {
			response.Diagnostics.AddWarning(
				"Certificate deployment not found.",
				fmt.Sprintf(
					"Certificate '%d' deployed to store '%s (%s)' was not found in Keyfactor Command, removing from state: ",
					certificateId,
					storeId,
					certificateAlias,
				)+err.Error(),
			)
			response.State.RemoveResource(ctx)
			return
		}
		response.Diagnostics.AddError(
			"Deployment read error.",
			fmt.Sprintf(
				"Unknown error during read status of deployment of certificate '%d' to store '%s (%s)': ",
				certificateId,
				storeId,
				certificateAlias,
			)+err.Error(),
		)
		// certificateData is nil: nothing below can be decided without it.
		return
	}
	for _, location := range certificateData.Locations {
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

	jobParams, jpDiags := jobParametersFromPlan(ctx, plan.JobParameters)
	response.Diagnostics.Append(jpDiags...)
	if response.Diagnostics.HasError() {
		return
	}
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
		// certificateData is nil: nothing below can be decided without it.
		return
	}

	// Initial presence check: a single inventory read. A read error is NOT "not deployed" (see Create).
	alreadyDeployed, presenceErr := deploymentPresentInInventory(ctx, kfClient, storeId, certificateAlias, certificateData)
	if presenceErr != nil {
		response.Diagnostics.AddError(
			"Deployment read error.",
			fmt.Sprintf(
				"Unable to read the inventory of store '%s' to check whether certificate '%d' (%s) is already deployed; "+
					"no deployment job was submitted: ",
				storeId,
				certificateId,
				certificateAlias,
			)+presenceErr.Error(),
		)
		return
	}

	// include_private_key changes never reach Update with a real change: they force replacement
	// (see ModifyPlan). Update only re-adds a missing entry.
	if !alreadyDeployed {
		addErr := addCertificateToStore(ctx, kfClient, jobParams, &plan)
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
					"Unknown error during validation of deploy of certificate '%d' to store '%s (%s)': ",
					certificateId,
					storeId,
					certificateAlias,
				)+vErr2.Error(),
			)
		}
	}

	if response.Diagnostics.HasError() {
		return
	}

	// Set state
	var result = CommandCertificateDeployment{
		ID:                types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
		CertificateId:     plan.CertificateId,
		StoreId:           plan.StoreId,
		CertificateAlias:  plan.CertificateAlias,
		KeyPassword:       plan.KeyPassword,
		JobParameters:     plan.JobParameters,
		Redeploy:          plan.Redeploy,
		Overwrite:         plan.Overwrite,
		SkipRemoval:       plan.SkipRemoval,
		IncludePrivateKey: plan.IncludePrivateKey,
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
					"Unknown error during removal of certificate '%d' from store '%s (%s)': ",
					certificateId,
					storeId,
					certificateAlias,
				)+validateErr.Error(),
			)
			break
		}
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
		IncludePrivateKey:  includePrivateKeyOrDefault(plan.IncludePrivateKey),
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

// jobParametersFromPlan converts the job_parameters map attribute to a Go map. A null or unknown
// map yields nil with no diagnostics; a conversion failure is returned to the caller instead of
// being dropped.
func jobParametersFromPlan(ctx context.Context, params types.Map) (map[string]string, diag.Diagnostics) {
	if params.Null || params.Unknown {
		return nil, nil
	}
	var out map[string]string
	diags := params.ElementsAs(ctx, &out, false)
	return out, diags
}

// inventoryPresence is the result of looking for a certificate (and the entry it would occupy) in
// a store's inventory.
type inventoryPresence struct {
	// CertificatePresent is true when certObj is in the store under the requested alias (or, for
	// matchEmptyAliasByLeafId lookups with no alias, anywhere in the store by leaf certificate ID).
	CertificatePresent bool
	// AliasOccupied is true when an inventory entry named certAlias exists, whichever certificate it
	// holds. It is only ever set for a non-empty alias: an alias-less deployment has no entry name to
	// compare, so the only entry that can be identified as the target is the certificate's own
	// (CertificatePresent).
	AliasOccupied bool
}

// inspectInventory performs a single inventory read and reports where certObj is and whether
// certAlias is already taken. See inventoryPresence.
func inspectInventory(
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
	matchEmptyAliasByLeafId bool,
) (inventoryPresence, error) {
	var res inventoryPresence
	inv, invErr := conn.GetCertStoreInventory(storeId)
	if invErr != nil {
		return res, invErr
	}
	// check if inv is empty or nil
	if inv == nil || len(*inv) == 0 {
		return res, nil
	}
	for _, cert := range *inv {
		if cert.Name == certAlias {
			if certAlias != "" {
				res.AliasOccupied = true
			}
			// Iterate through Certificates in the store and check if the certificate we're looking for is there
			for _, iCert := range cert.Certificates {
				if iCert.Id == certObj.Id {
					res.CertificatePresent = true
				}
			}
		} else if matchEmptyAliasByLeafId && certAlias == "" {
			// if not alias is provided then just compare cert ID of the leaf node
			if len(cert.Ids) > 0 && cert.Ids[0] == certObj.Id { //TODO: This may not be the best way to do this as a cert ID can show up multiple times in a store
				res.CertificatePresent = true
			}
		}
	}
	return res, nil
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
	res, err := inspectInventory(conn, storeId, certAlias, certObj, matchEmptyAliasByLeafId)
	return res.CertificatePresent, err
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
	return certificateInInventory(ctx, conn, storeId, certAlias, certObj, false)
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
// certificate is present in the store : matched by alias, or by leaf certificate ID when
// no alias is set. Matching semantics are shared with validateDeployment.
func deploymentPresentInInventory(
	ctx context.Context,
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
) (bool, error) {
	return certificateInInventory(ctx, conn, storeId, certAlias, certObj, true)
}

// deploymentInventoryPresence is deploymentPresentInInventory plus whether the target alias is
// occupied by any entry (see inventoryPresence), from the same single inventory read.
func deploymentInventoryPresence(
	conn *api.Client,
	storeId string,
	certAlias string,
	certObj *api.GetCertificateResponse,
) (inventoryPresence, error) {
	return inspectInventory(conn, storeId, certAlias, certObj, true)
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

// includePrivateKeyChangeRequiresReplace reports whether moving include_private_key from
// state to plan must replace the deployment. Null means the default (true), so null<->true is
// not a change. An unknown plan value never reaches this function in a successful plan:
// ModifyPlan rejects it (see includePrivateKeyUnknownDiagnostic), because it cannot be proven
// unchanged.
func includePrivateKeyChangeRequiresReplace(state, plan types.Bool) bool {
	return includePrivateKeyOrDefault(state) != includePrivateKeyOrDefault(plan)
}

// includePrivateKeyUnknownDiagnostic returns the plan-time error text for an include_private_key
// whose planned value is unknown. include_private_key decides whether an existing deployment is
// replaced (a change in the effective value replaces it), and an unknown value cannot be classified
// as changed or unchanged during plan.
func includePrivateKeyUnknownDiagnostic() (summary, detail string) {
	return "include_private_key must be known at plan time",
		"include_private_key must be known at plan time (use a literal or input variable); it decides whether the " +
			"deployment is replaced, and a value that is only known after apply cannot be classified as a change or " +
			"not."
}

// includePrivateKeyReplaceBlockedBySkipRemoval reports whether an include_private_key
// replacement would be unsafe because skip_removal is true in the PRIOR STATE. Delete reads
// skip_removal from prior state, so only a state value of true makes the replace's delete step
// leave the existing store entry in place (and the key change unguaranteed). Setting
// skip_removal = true in the same apply as the change is safe (the removal still runs against
// the prior state), and an unknown or null plan value is irrelevant, so the plan value is not
// consulted.
func includePrivateKeyReplaceBlockedBySkipRemoval(stateSkip types.Bool) bool {
	return !stateSkip.Null && !stateSkip.Unknown && stateSkip.Value
}

// existingEntryPrivateKeyDiagnostic builds the Create error for include_private_key = false when
// the certificate is already deployed to the store entry.
func existingEntryPrivateKeyDiagnostic(certificateId interface{}, storeId, certificateAlias string) (summary, detail string) {
	return "Existing deployment may contain the private key.",
		fmt.Sprintf(
			"Certificate '%v' is already deployed to '%s (%s)' and include_private_key = false was requested. "+
				"The existing store entry may contain the private key, and it cannot be stripped in place. "+
				"Remove the entry from the store first, or set include_private_key = true (or remove the attribute). "+
				"Note: changing include_private_key is not supported with lifecycle { create_before_destroy = true }, "+
				"because the replacement is created while the old entry still exists; the replace must delete the "+
				"existing deployment first (the default).",
			certificateId, storeId, certificateAlias,
		)
}

// occupiedAliasPrivateKeyDiagnostic builds the Create error for include_private_key = false when the
// target alias is already held by an entry for a different certificate.
func occupiedAliasPrivateKeyDiagnostic(certificateId interface{}, storeId, certificateAlias string) (summary, detail string) {
	return "Target alias is occupied by another store entry.",
		fmt.Sprintf(
			"The alias '%s' in store '%s' is already occupied by an entry for a different certificate, and "+
				"include_private_key = false was requested for certificate '%v'. Deploying would overwrite that entry without "+
				"a private key, and the provider cannot verify that no key material of the existing entry would remain. "+
				"Remove the entry from the store first, choose a different certificate_alias, or set include_private_key = true "+
				"(or remove the attribute).",
			certificateAlias, storeId, certificateId,
		)
}

// ModifyPlan owns the include_private_key replace decision (there is deliberately no attribute
// plan modifier for it, so the decision lives in one place). It is a resource-level hook rather
// than an attribute modifier because it must (a) read skip_removal from the PRIOR STATE (the
// replace's delete step does), (b) reject an unknown include_private_key outright, and (c) make
// one consolidated decision across attributes. (A tfsdk.RequiresReplaceIf on this attribute would
// evaluate a null config for a non-Computed attribute just like any other value; null is not the
// reason it is not used. It is attached to one attribute, so it could not reject an unknown value
// with this message, read skip_removal from prior state, or see the other attributes' replacements.)
//
// It rejects, at plan time:
//  1. an include_private_key that is unknown for an existing deployment, unless the deployment is
//     already being replaced for another reason (the value then resolves before Create, which has
//     its own guards on the resolved value);
//  2. an include_private_key change that would replace the deployment while skip_removal is true
//     in the current state: the replace's delete step reads skip_removal from prior state and so
//     could not remove the existing entry;
//  3. any other replacement (certificate_id, certificate_store_id, certificate_alias,
//     key_password, redeploy = true) while skip_removal is true in the current state and the
//     planned include_private_key is false: Delete would leave the entry in the store and the
//     replacement's Create would then refuse it (it cannot strip an existing private key).
//
// Otherwise a change in the effective include_private_key value (null means true) marks the
// attribute as requiring replacement. The framework passes the resource-level ModifyPlan a fresh
// RequiresReplace slice, so the decision in (3) is computed by running the schema's attribute
// plan modifiers (deploymentSchemaRequiresReplace) rather than read from resp.RequiresReplace.
func (r resourceCommandCertificateDeployment) ModifyPlan(
	ctx context.Context,
	req tfsdk.ModifyResourcePlanRequest,
	resp *tfsdk.ModifyResourcePlanResponse,
) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var stateObj, planObj CommandCertificateDeployment
	if d := req.State.Get(ctx, &stateObj); d.HasError() {
		resp.Diagnostics.Append(d...)
		return
	}
	if d := req.Plan.Get(ctx, &planObj); d.HasError() {
		resp.Diagnostics.Append(d...)
		return
	}
	// An unknown planned value cannot be classified as a change or not (see
	// includePrivateKeyUnknownDiagnostic). Only an existing deployment can be replaced, so a
	// value that is unknown while creating a new deployment is resolved before Create runs.
	if planObj.IncludePrivateKey.Unknown {
		// When the deployment is already being replaced for another reason the value is not what
		// decides the replace, and it resolves before Create runs (Create has its own guards on the
		// resolved value), so there is nothing to reject. Only when nothing else replaces the
		// deployment does the unknown value decide whether it is replaced, and that cannot be known.
		replaced, d := deploymentSchemaRequiresReplace(ctx, req)
		resp.Diagnostics.Append(d...)
		if d.HasError() || replaced {
			return
		}
		summary, detail := includePrivateKeyUnknownDiagnostic()
		resp.Diagnostics.AddAttributeError(path.Root("include_private_key"), summary, detail)
		return
	}
	if includePrivateKeyChangeRequiresReplace(stateObj.IncludePrivateKey, planObj.IncludePrivateKey) {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("include_private_key"))
		if includePrivateKeyReplaceBlockedBySkipRemoval(stateObj.SkipRemoval) {
			resp.Diagnostics.AddAttributeError(
				path.Root("include_private_key"),
				"include_private_key cannot be changed while skip_removal is true in the current state",
				"Changing include_private_key replaces the deployment, but while skip_removal is true in the current "+
					"state the replace's delete step does not remove the existing certificate entry from the store, so "+
					"the private-key change cannot be guaranteed (the existing entry may keep its private key). "+
					"Apply skip_removal = false first, then change include_private_key.",
			)
		}
		return
	}
	// include_private_key itself is unchanged. A replacement for any other reason is still unsafe
	// when the replacement must deploy without the private key but Delete will not remove the entry.
	if !includePrivateKeyReplaceBlockedBySkipRemoval(stateObj.SkipRemoval) || includePrivateKeyOrDefault(planObj.IncludePrivateKey) {
		return
	}
	replaced, d := deploymentSchemaRequiresReplace(ctx, req)
	resp.Diagnostics.Append(d...)
	if d.HasError() || !replaced {
		return
	}
	resp.Diagnostics.AddAttributeError(
		path.Root("include_private_key"),
		"Cannot replace a deployment with include_private_key = false while skip_removal is true in the current state",
		"This change replaces the deployment, but skip_removal is true in the current state, so the replace's delete "+
			"step will not remove the existing certificate entry from the store. The replacement's create step would "+
			"then find that entry and refuse to adopt it, because an existing entry may contain the private key and "+
			"include_private_key = false cannot strip it. Apply skip_removal = false first, then make this change.",
	)
}

// deploymentSchemaRequiresReplace reports whether any of the resource's attribute plan modifiers
// would require replacement of the resource for this plan. It runs the same modifiers, with the
// same inputs, that the framework runs before the resource-level ModifyPlan (whose own
// resp.RequiresReplace starts empty and so does not reflect them).
func deploymentSchemaRequiresReplace(ctx context.Context, req tfsdk.ModifyResourcePlanRequest) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	schema := req.State.Schema
	names := make([]string, 0, len(schema.Attributes))
	for name, a := range schema.Attributes {
		if len(a.PlanModifiers) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		p := path.Root(name)
		var attrState, attrPlan, attrConfig attr.Value
		diags.Append(req.State.GetAttribute(ctx, p, &attrState)...)
		diags.Append(req.Plan.GetAttribute(ctx, p, &attrPlan)...)
		if diags.HasError() {
			return false, diags
		}
		if cd := req.Config.GetAttribute(ctx, p, &attrConfig); cd.HasError() || attrConfig == nil {
			// No usable config (it is always present when the framework calls ModifyPlan);
			// fall back to the planned value so the modifiers evaluate state vs plan.
			attrConfig = attrPlan
		}
		modReq := tfsdk.ModifyAttributePlanRequest{
			AttributePath:   p,
			Config:          req.Config,
			State:           req.State,
			Plan:            req.Plan,
			AttributeConfig: attrConfig,
			AttributeState:  attrState,
			AttributePlan:   attrPlan,
		}
		for _, m := range schema.Attributes[name].PlanModifiers {
			modResp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: attrPlan}
			m.Modify(ctx, modReq, modResp)
			diags.Append(modResp.Diagnostics...)
			if diags.HasError() {
				return false, diags
			}
			if modResp.RequiresReplace {
				return true, diags
			}
		}
	}
	return false, diags
}

// includePrivateKeyOrDefault returns the configured include_private_key value,
// defaulting to true (the historical behavior) when it is null or unknown.
func includePrivateKeyOrDefault(v types.Bool) bool {
	if v.Null || v.Unknown {
		return true
	}
	return v.Value
}
