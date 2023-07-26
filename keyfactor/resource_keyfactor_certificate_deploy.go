package keyfactor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"strings"
	"time"
)

type resourceKeyfactorCertificateDeploymentType struct{}

func (r resourceKeyfactorCertificateDeploymentType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
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
				Required:      true,
				Description:   "A string providing an alias to be used for the certificate upon entry into the certificate store. The function of the alias varies depending on the certificate store type. Please ensure that the alias is lowercase, or problems can arise in Terraform Plan.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"key_password": {
				Type:          types.StringType,
				Optional:      true,
				Sensitive:     true,
				Description:   "Password that protects PFX certificate, if the certificate was enrolled using PFX enrollment, or is password protected in general. This value cannot change, and Terraform will throw an error if a change is attempted.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
		},
	}, nil
}

func (r resourceKeyfactorCertificateDeploymentType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceKeyfactorCertificateDeployment{
		p: *(p.(*provider)),
	}, nil
}

type resourceKeyfactorCertificateDeployment struct {
	p provider
}

func (r resourceKeyfactorCertificateDeployment) Create(ctx context.Context, request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan KeyfactorCertificateDeployment
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
	keyPassword := plan.KeyPassword.Value
	hid := fmt.Sprintf("%v-%s-%s", certificateId, storeId, certificateAlias)

	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "certificate_store_id", storeId)
	ctx = tflog.SetField(ctx, "certificate_alias", certificateAlias)
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
			fmt.Sprintf("Unknown error during read status of deployment of certificate '%s' to store '%s (%s)': "+err.Error(), certificateId, storeId, certificateAlias),
		)
	}

	//sans := plan.SANs
	//metadata := plan.Metadata.Elems
	//vErr := validateCertificatesInStore(ctx, kfClient, certificateIdInt, storeId, 1) // Initial check to see if the cert is already deployed
	vErr := validateDeployment(ctx, kfClient, storeId, certificateAlias, certificateData, 1) // Initial check to see if the cert is already deployed
	if vErr == nil {
		response.Diagnostics.AddWarning(
			"Duplicate deployment.",
			fmt.Sprintf("Certificate '%v' is already deployed to '%s (%s)'", certificateId, storeId, certificateAlias),
		)
	} else {
		addErr := addCertificateToStore(ctx, kfClient, certificateIdInt, certificateAlias, keyPassword, storeId)
		if addErr != nil {
			response.Diagnostics.AddError(
				"Certificate deployment error",
				fmt.Sprintf("Unknown error during deploy of certificate '%v'(%s) to store '%s': "+addErr.Error(), certificateId, certificateAlias, storeId),
			)
		}
		if response.Diagnostics.HasError() {
			return
		}

		//vErr2 := validateCertificatesInStore(ctx, kfClient, certificateIdInt, storeId, 100000)
		vErr2 := validateDeployment(ctx, kfClient, storeId, certificateAlias, certificateData, 1000000) // Initial check to see if the cert is already deployed
		if vErr2 != nil {
			response.Diagnostics.AddError(
				"Deployment validation error.",
				fmt.Sprintf("Unknown error during validation of deploy of certificate '%s' to store '%s (%s)': "+vErr.Error(), certificateId, storeId, certificateAlias),
			)
		}
		if response.Diagnostics.HasError() {
			return
		}
	}

	// Set state
	var result = KeyfactorCertificateDeployment{
		ID:               types.String{Value: fmt.Sprintf("%x", sha256.Sum256([]byte(hid)))},
		CertificateId:    plan.CertificateId,
		StoreId:          plan.StoreId,
		CertificateAlias: plan.CertificateAlias,
		KeyPassword:      plan.KeyPassword,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

}

func (r resourceKeyfactorCertificateDeployment) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	var state KeyfactorCertificateDeployment
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
			fmt.Sprintf("Unknown error during read status of deployment of certificate '%s' to store '%s (%s)': "+err.Error(), certificateId, storeId, certificateAlias),
		)
	}
	locations := certificateData.Locations
	for _, location := range locations {
		tflog.Debug(ctx, fmt.Sprintf("Certificate %v stored in location: %v", certificateIdInt, location))
	}

	// Set state
	var result = KeyfactorCertificateDeployment{
		ID:               state.ID,
		CertificateId:    state.CertificateId,
		StoreId:          state.StoreId,
		CertificateAlias: state.CertificateAlias,
		KeyPassword:      state.KeyPassword,
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceKeyfactorCertificateDeployment) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	// Get plan values
	var plan KeyfactorCertificate
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state KeyfactorCertificate
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

func (r resourceKeyfactorCertificateDeployment) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	var state KeyfactorCertificateDeployment
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
				fmt.Sprintf("Certificate deployment '%v' to store '%s (%s)' not found, removing from state.", certificateId, storeId, certificateAlias),
			)
		} else {
			response.Diagnostics.AddError(
				"Certificate deployment error",
				fmt.Sprintf("Unknown error during removal of certificate '%s' from store '%s (%s)': "+err.Error(), certificateId, storeId, certificateAlias),
			)
		}

	}

	if response.Diagnostics.HasError() {
		return
	}
	response.State.RemoveResource(ctx)
}

func (r resourceKeyfactorCertificateDeployment) ImportState(ctx context.Context, request tfsdk.ImportResourceStateRequest, response *tfsdk.ImportResourceStateResponse) {
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
func addCertificateToStore(ctx context.Context, conn *api.Client, certificateId int, certificateAlias string, keyPassword string, storeId string) error {
	var storesStruct []api.CertificateStore

	storeRequest := new(api.CertificateStore)

	storeRequest.CertificateStoreId = storeId
	storeRequest.Alias = certificateAlias

	storeRequest.IncludePrivateKey = true //todo: make this configurable
	storeRequest.Overwrite = true
	storeRequest.PfxPassword = keyPassword
	storesStruct = append(storesStruct, *storeRequest)

	// We want Keyfactor to immediately apply these changes.
	tflog.Debug(ctx, "Creating immediate request to add certificate to store")

	schedule := &api.InventorySchedule{
		Immediate: boolToPointer(true),
	}
	config := &api.AddCertificateToStore{
		CertificateId:     certificateId,
		CertificateStores: &storesStruct,
		InventorySchedule: schedule,
	}
	tflog.Debug(ctx, fmt.Sprintf("Adding certificate %v to Keyfactor store %v", certificateId, storeId))
	_, err := conn.AddCertificateToStores(config)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error adding certificate %v to Keyfactor store %v: %v", certificateId, storeId, err))
		return err
	}
	tflog.Debug(ctx, fmt.Sprintf("Successfully added certificate %v to Keyfactor store %v", certificateId, storeId))
	return nil
}

func validateUndeployment(ctx context.Context, conn *api.Client, storeId string, certificateId int, certAlias string, certObj *api.GetCertificateResponse, maxIterations int) error {
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
			tflog.Debug(ctx, fmt.Sprintf("Certificate '%s'(%v) found in Keyfactor Command store '%s'(%v). Retrying in %v seconds", certObj.Thumbprint, certObj.Id, certAlias, storeId, retryDelay))
			time.Sleep(time.Duration(retryDelay) * time.Second)
			retryDelay = retryDelay * 2
			if retryDelay > 60 {
				retryDelay = 60
			}
			deployed = false
		} else {
			break
		}
	}
	if deployed {
		return fmt.Errorf("unable to remove certificate '%s'(%s) from Keyfactor Command store %v", certObj.Thumbprint, certAlias, storeId)
	}
	return nil
}

func validateDeployment(ctx context.Context, conn *api.Client, storeId string, certAlias string, certObj *api.GetCertificateResponse, maxIterations int) error {
	valid := false
	tflog.Debug(ctx, fmt.Sprintf("Validating Keyfactor Command store %v inventory has been updated with %s", storeId, certAlias))
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
			}
			if valid {
				break
			}
		}
		if !valid {
			tflog.Debug(ctx, fmt.Sprintf("Certificate %s not found in Keyfactor store %v. Retrying in %v seconds", certAlias, storeId, retryDelay))
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

func validateCertificatesInStore(ctx context.Context, conn *api.Client, certificateId int, storeId string, maxIterations int) error {
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
			tflog.Debug(ctx, fmt.Sprintf("Certificate %v not found in Keyfactor store %v. Retrying in %v seconds", certificateId, storeId, retryDelay))
			time.Sleep(time.Duration(retryDelay) * time.Second)
		}
	}
	if !valid {
		return fmt.Errorf("validateCertificatesInStore timed out. certificate could deploy eventually, but terraform change operation will fail. run terraform plan later to verify that the certificate was deployed successfully")
	}
	return nil
}

func removeCertificateAliasFromStore(ctx context.Context, conn *api.Client, certificateStores *[]api.CertificateStore, certId int, certAlias string) error {
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
		validateErr := validateUndeployment(ctx, conn, store.CertificateStoreId, certId, certAlias, certificateData, 100000)
		if validateErr != nil {
			return validateErr
		}
	}

	return nil
}
