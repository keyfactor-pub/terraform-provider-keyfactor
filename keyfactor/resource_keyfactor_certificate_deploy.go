package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

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
				Description: "If true, any existing certificate with the same alias will be overwritten. If false, an error will be returned if a certificate with the same alias already exists. Default value is `true`.",
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
		},
		Description: "Used to schedule a certificate deployment(" +
			"/management) job on Keyfactor Command using the `/OrchestratorJobs/Custom` API to deploy certificates to" +
			" `keyfactor_certificate_store` resources. " +
			"*NOTE:* The jobs are run asynchronously, and depend on orchestrator agent check in schedules. The provider will wait for the job to complete successfully and may run for a long time.",
		MarkdownDescription: `
Used to schedule a certificate deployment(/management) job on Keyfactor Command using the "/OrchestratorJobs/Custom" 
API to deploy certificates to "keyfactor_certificate_store" resources.

> [!IMPORTANT]
> Orchestrator agent jobs are run asynchronously outside of Terraform, and depend on orchestrator agent check in schedules.
> A "keyfactor_certificate_deployment" *will not finish* successfully until the destination certificate store's certificate 
> inventory has been updated to include the deployed certificate.
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
				"Unknown error during read status of deployment of certificate '%s' to store '%s (%s)': "+err.Error(),
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

		//vErr2 := validateCertificatesInStore(ctx, kfClient, certificateIdInt, storeId, 100000)
		vErr2 := validateDeployment(
			ctx,
			kfClient,
			storeId,
			certificateAlias,
			certificateData,
			1000000,
		) // Initial check to see if the cert is already deployed
		if vErr2 != nil {
			response.Diagnostics.AddError(
				"Deployment validation error.",
				fmt.Sprintf(
					"Unknown error during validation of deploy of certificate '%s' to store '%s (%s)': "+vErr.Error(),
					certificateId,
					storeId,
					certificateAlias,
				),
			)
		}
		if response.Diagnostics.HasError() {
			return
		}
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
	}

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
	// Get plan values
	var plan CommandCertificate
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state CommandCertificate
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// API Actions

	// Set state
	tflog.Error(ctx, "Update called on certificate deployment resource")
	response.Diagnostics.AddError(
		"Certificate deployment updates not implemented.",
		fmt.Sprintf("Error, only create and delete actions are supported for certificate deployments."),
	)
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
		// If no alias is provided then lookup the cert ID in keyfactor and use the alias from there
		lookupCertResp, lkErr := kfClient.GetCertificateContext(&api.GetCertificateContextArgs{Id: int(certificateId)})
		if lkErr != nil {
			response.Diagnostics.AddWarning(
				"Certificate removal error.",
				fmt.Sprintf("Error looking up certificate '%s' in Keyfactor: "+lkErr.Error(), certificateId),
			)
			response.State.RemoveResource(ctx)
			return
		}
		certificateAlias = lookupCertResp.Thumbprint // TODO: This is not always valid alias can be non-thumbprint
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

	err := removeCertificateAliasFromStore(ctx, kfClient, &diff, certId, certificateAlias)
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
		} else {
			response.Diagnostics.AddError(
				"Certificate deployment error",
				fmt.Sprintf(
					"Unknown error during removal of certificate '%s' from store '%s (%s)': "+err.Error(),
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
	implicitOverwrite := plan.Overwrite.Null || plan.Overwrite.Value
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

// Extracted helper function to avoid duplication
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

	if strings.Contains(err.Error(), "does not exist in certificate store") && implicitOverwrite {
		if config.CertificateStores != nil && len(*config.CertificateStores) > 0 {
			for i := range *config.CertificateStores {
				(*config.CertificateStores)[i].Overwrite = false
			}
		}
		resp, err = conn.AddCertificateToStores(config)
		if err == nil {
			tflog.Trace(ctx, fmt.Sprintf("Response from Keyfactor on retry: %v", resp))
			return nil
		}
	}

	tflog.Error(ctx, fmt.Sprintf("Error adding certificate %v to Keyfactor store %v: %v", certificateId, storeId, err))
	return err
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
		inv, invErr := conn.GetCertStoreInventory(storeId)
		if invErr != nil {
			return invErr
		}
		// check if inv is empty or nil
		if inv == nil || len(*inv) == 0 {
			deployed = false
			break
		}
		for _, cert := range *inv {
			if cert.Name == certAlias {
				// Iterate through Certificates in the store and check if the certificate we're looking for is there
				for _, iCert := range cert.Certificates {
					if iCert.Id == certObj.Id {
						deployed = true
						break
					}
				}
			}
			if deployed {
				break
			}
		}
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
			deployed = false
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
		inv, invErr := conn.GetCertStoreInventory(storeId)
		if invErr != nil {
			return invErr
		}
		for _, cert := range *inv {
			if cert.Name == certAlias {
				// Iterate through Certificates in the store and check if the certificate we're looking for is there
				for _, iCert := range cert.Certificates {
					if iCert.Id == certObj.Id {
						valid = true
						break
					}
				}
			} else if certAlias == "" {
				// if not alias is provided then just compare cert ID of the leaf node
				if len(cert.Ids) > 0 && cert.Ids[0] == certObj.Id { //TODO: This may not be the best way to do this as a cert ID can show up multiple times in a store
					valid = true
					break
				}
			}
			if valid {
				break
			}
		}
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

func removeCertificateAliasFromStore(
	ctx context.Context,
	conn *api.Client,
	certificateStores *[]api.CertificateStore,
	certId int,
	certAlias string,
) error {
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
		return cerErr
	}

	_, err := conn.RemoveCertificateFromStores(config)

	if err != nil {
		return err
	}

	//iterate through stores and validate that the certificate is no longer in the store
	for _, store := range *certificateStores {
		validateErr := validateUndeployment(
			ctx,
			conn,
			store.CertificateStoreId,
			certId,
			certAlias,
			certificateData,
			100000,
		)
		if validateErr != nil {
			return validateErr
		}
	}

	return nil
}
