package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"log"
	"strconv"
	"strings"
)

type resourceCertificateStoreType struct{}

func (r resourceCertificateStoreType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"container_id": {
				Type:          types.Int64Type,
				Optional:      true,
				Description:   "Container identifier of the store's associated certificate store container.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"client_machine": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Client machine name; value depends on certificate store type. See API reference guide",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"store_path": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Path to the new certificate store on a target. Format varies depending on type.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"store_type": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Short name of certificate store type. See API reference guide",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"approved": {
				Type:       types.BoolType,
				Attributes: nil,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},

				Description:         "Bool that indicates the approval status of store created. Default is true, omit if unsure.",
				MarkdownDescription: "",
				Required:            false,
				Optional:            true,
				Computed:            false,
				PlanModifiers:       []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"create_if_missing": {
				Type:          types.BoolType,
				Optional:      true,
				Description:   "Bool that indicates if the store should be created with information provided. Valid only for JKS type, omit if unsure.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"properties": {
				Type:          types.MapType{ElemType: types.StringType},
				Optional:      true,
				Description:   "Certificate properties specific to certificate store type configured as key-value pairs.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"agent_id": {
				Type:          types.StringType,
				Required:      true,
				Description:   "String indicating the Keyfactor Command GUID of the orchestrator for the created store.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"agent_assigned": {
				Type:     types.BoolType,
				Optional: true,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
				Description:   "Bool indicating if there is an orchestrator assigned to the new certificate store.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"container_name": {
				Type:          types.StringType,
				Optional:      true,
				Description:   "Name of certificate store's associated container, if applicable.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"inventory_schedule": {
				Type:     types.StringType,
				Optional: true,
				Description: `String indicating the schedule for inventory updates. Valid formats are:
					"immediate" - schedules and immediate job
					"1d" - schedules a daily job
					"12h" - schedules a job every 12 hours
					"30m" - schedules a job every 30 minutes
				`,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"set_new_password_allowed": {
				Type:          types.BoolType,
				Optional:      true,
				Description:   "Indicates whether the store password can be changed.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"password": {
				Type:          types.StringType,
				Optional:      true,
				Description:   "Sets password for certificate store.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Keyfactor certificate store GUID.",
			},
		},
	}, nil
}

func (r resourceCertificateStoreType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceCertificateStore{
		p: *(p.(*provider)),
	}, nil
}

type resourceCertificateStore struct {
	p provider
}

func (r resourceCertificateStore) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan CertificateStore
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	//certificateStoreId := plan.ID.Value
	//ctx = tflog.SetField(ctx, "id", certificateStoreId)
	tflog.Info(ctx, "Create called on certificate store resource")

	csType, csTypeErr := r.p.client.GetCertificateStoreTypeByName(plan.StoreType.Value)
	if csTypeErr != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store type.",
			fmt.Sprintf("Could not retrieve certificate store type '%s' from Keyfactor"+csTypeErr.Error(), plan.StoreType.Value),
		)
		return
	}

	var containerId int
	if !plan.ContainerID.Null {
		containerId = int(plan.ContainerID.Value)
	}

	var properties map[string]string
	if plan.Properties.Elems != nil {
		diags = plan.Properties.ElementsAs(ctx, &properties, false)

	}
	schedule, err := createInventorySchedule(plan.InventorySchedule.Value) // TODO: Implement inventory schedule
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid inventory schedule.",
			fmt.Sprintf("Could not create inventory schedule: %s", err.Error()),
		)
		return
	}

	var containerIdP *int
	if containerId <= 0 {
		containerIdP = nil
	} else {
		containerIdP = &containerId
	}

	var storePassFormatted *api.StorePasswordConfig
	if plan.Password.Null {
		storePassFormatted = nil
	} else {
		storePassFormatted = createPasswordConfig(plan.Password.Value)
	}

	newStoreArgs := &api.CreateStoreFctArgs{
		ContainerId:           containerIdP,
		ClientMachine:         plan.ClientMachine.Value,
		StorePath:             plan.StorePath.Value,
		CertStoreType:         csType.StoreType,
		Approved:              &plan.Approved.Value,
		CreateIfMissing:       &plan.CreateIfMissing.Value,
		Properties:            properties,
		AgentId:               plan.AgentId.Value,
		AgentAssigned:         &plan.AgentAssigned.Value,
		ContainerName:         &plan.ContainerName.Value,
		InventorySchedule:     schedule,
		SetNewPasswordAllowed: &plan.SetNewPasswordAllowed.Value,
		Password:              storePassFormatted,
	}

	createStoreResponse, err := kfClient.CreateStore(newStoreArgs)
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating certificate store",
			"Error creating certificate store: %s"+err.Error(),
		)
		return
	}

	// Set state
	var result = CertificateStore{
		ID: types.String{Value: createStoreResponse.Id},
		ContainerID: types.Int64{
			Null:  plan.ContainerID.Null,
			Value: int64(createStoreResponse.ContainerId),
		},
		ClientMachine:         types.String{Value: createStoreResponse.ClientMachine},
		StorePath:             types.String{Value: createStoreResponse.Storepath},
		StoreType:             types.String{Value: plan.StoreType.Value},
		Approved:              plan.Approved,
		CreateIfMissing:       plan.CreateIfMissing,
		Properties:            plan.Properties,
		AgentId:               types.String{Value: createStoreResponse.AgentId},
		AgentAssigned:         plan.AgentAssigned,
		ContainerName:         plan.ContainerName,
		InventorySchedule:     plan.InventorySchedule,
		SetNewPasswordAllowed: plan.SetNewPasswordAllowed,
		Password:              plan.Password,
		//Certificates:          types.List{ElemType: types.Int64Type, Elems: []attr.Value{}},
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

}

func (r resourceCertificateStore) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	var state CertificateStore
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate store resource")
	certificateStoreId := state.ID.Value

	tflog.SetField(ctx, "id", certificateStoreId)

	_, err := r.p.client.GetCertificateStoreByID(certificateStoreId)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading certificate store",
			"Error reading certificate store: %s"+err.Error(),
		)
		return
	}

	//password := state.Password.Value
	//tflog.Trace(ctx, fmt.Sprintf("Password for store %s: %s", certificateStoreId, password))

	// Set state
	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCertificateStore) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	// Get plan values
	var plan CertificateStore
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state CertificateStore
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var properties map[string]string
	if plan.Properties.Elems != nil {
		diags = plan.Properties.ElementsAs(ctx, &properties, false)
	}

	// Generate API request body from plan
	containerId := int(plan.ContainerID.Value)
	csType, csTypeErr := r.p.client.GetCertificateStoreTypeByName(plan.StoreType.Value)
	if csTypeErr != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store type.",
			fmt.Sprintf("Could not retrieve certificate store type '%s' from Keyfactor"+csTypeErr.Error(), plan.StoreType.Value),
		)
		return
	}
	schedule, err := createInventorySchedule(plan.InventorySchedule.Value) // TODO: Implement inventory schedule
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid inventory schedule.",
			fmt.Sprintf("Could not create inventory schedule: %s", err.Error()),
		)
		return
	}

	var containerIdP *int
	if plan.ContainerID.Null {
		containerIdP = nil
	} else {
		containerIdP = &containerId
	}

	var storePassFormatted *api.StorePasswordConfig
	if plan.Password.Null {
		storePassFormatted = nil
	} else {
		storePassFormatted = createPasswordConfig(plan.Password.Value)
	}

	updateStoreArgs := &api.UpdateStoreFctArgs{
		Id: state.ID.Value,
		CreateStoreFctArgs: api.CreateStoreFctArgs{
			ContainerId:           containerIdP,
			ClientMachine:         plan.ClientMachine.Value,
			StorePath:             plan.StorePath.Value,
			CertStoreType:         csType.StoreType,
			Approved:              &plan.Approved.Value,
			CreateIfMissing:       &plan.CreateIfMissing.Value,
			Properties:            properties,
			AgentId:               plan.AgentId.Value,
			AgentAssigned:         &plan.AgentAssigned.Value,
			ContainerName:         &plan.ContainerName.Value,
			InventorySchedule:     schedule,
			SetNewPasswordAllowed: &plan.SetNewPasswordAllowed.Value,
			Password:              storePassFormatted,
		}}

	updateResponse, err := r.p.client.UpdateStore(updateStoreArgs)
	if err != nil {
		response.Diagnostics.AddError(
			"Error updating certificate store",
			"Error updating certificate store: %s"+err.Error(),
		)
		return
	}

	result := CertificateStore{
		ID:          types.String{Value: state.ID.Value},
		ContainerID: types.Int64{Value: int64(updateResponse.ContainerId)},
		//ClientMachine:   types.String{Value: updateResponse.ClientMachine},
		ClientMachine:         plan.ClientMachine,
		StorePath:             plan.StorePath,
		StoreType:             plan.StoreType,
		Approved:              plan.Approved,
		CreateIfMissing:       plan.CreateIfMissing,
		Properties:            plan.Properties,
		AgentId:               plan.AgentId,
		AgentAssigned:         plan.AgentAssigned,
		ContainerName:         plan.ContainerName,
		InventorySchedule:     plan.InventorySchedule,
		SetNewPasswordAllowed: plan.SetNewPasswordAllowed,
		Password:              plan.Password,
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCertificateStore) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	var state CertificateStore
	diags := request.State.Get(ctx, &state)
	kfClient := r.p.client

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get order ID from state
	certificateStoreId := state.ID.Value
	tflog.SetField(ctx, "id", certificateStoreId)

	// Delete order by calling API
	log.Println("[INFO] Deleting certificate resource")

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.

	tflog.Info(ctx, fmt.Sprintf("Revoking certificate %s in Keyfactor", certificateStoreId))

	err := kfClient.DeleteCertificateStore(certificateStoreId)
	if err != nil {
		response.Diagnostics.AddError("Certificate store delete error.", fmt.Sprintf("Could not delete certificate store '%s' on Keyfactor: "+err.Error(), certificateStoreId))
		return
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceCertificateStore) ImportState(ctx context.Context, request tfsdk.ImportResourceStateRequest, response *tfsdk.ImportResourceStateResponse) {
	var state CertificateStore

	tflog.Info(ctx, "Read called on certificate store resource")
	certificateStoreId := state.ID.Value

	tflog.SetField(ctx, "id", certificateStoreId)

	readResponse, err := r.p.client.GetCertificateStoreByID(certificateStoreId)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading certificate store",
			"Error reading certificate store: %s"+err.Error(),
		)
		return
	}

	password := state.Password.Value
	tflog.Trace(ctx, fmt.Sprintf("Password for store %s: %s", certificateStoreId, password))

	if err != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+err.Error(), certificateStoreId),
		)
		return
	}

	csType, csTypeErr := r.p.client.GetCertificateStoreType(readResponse.CertStoreType)
	if csTypeErr != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate store type '%s' from Keyfactor: "+err.Error(), readResponse.CertStoreType),
		)
		return
	}
	// Set state
	result := CertificateStore{
		ID:              types.String{Value: state.ID.Value},
		ContainerID:     types.Int64{Value: int64(readResponse.ContainerId)},
		ClientMachine:   types.String{Value: readResponse.ClientMachine},
		StorePath:       types.String{Value: readResponse.StorePath},
		StoreType:       types.String{Value: csType.Name},
		Approved:        types.Bool{Value: readResponse.Approved},
		CreateIfMissing: types.Bool{Value: readResponse.CreateIfMissing},
		//Properties:            plan.Properties,
		AgentId:       types.String{Value: readResponse.AgentId},
		AgentAssigned: types.Bool{Value: readResponse.AgentAssigned},
		ContainerName: types.String{Value: readResponse.ContainerName},
		InventorySchedule: types.String{
			Unknown: false,
			Null:    true,
			Value:   fmt.Sprintf("%v", readResponse.InventorySchedule),
		},
		SetNewPasswordAllowed: types.Bool{Value: readResponse.SetNewPasswordAllowed},
		//Password:              plan.Password,
	}
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func createPasswordConfig(p string) *api.StorePasswordConfig {
	password := stringToPointer(p)
	res := &api.StorePasswordConfig{
		Value: password,
	}

	return res
}

func createInventorySchedule(interval string) (*api.InventorySchedule, error) {
	inventorySchedule := &api.InventorySchedule{}

	if interval == "immediate" {
		immediate := true
		inventorySchedule.Immediate = &immediate
	} else {
		if strings.HasSuffix(interval, "m") {
			minutes, err := strconv.Atoi(interval[:len(interval)-1])
			if err != nil {
				return nil, err
			}
			iv := &api.InventoryInterval{Minutes: minutes}
			inventorySchedule.Interval = iv
			return inventorySchedule, nil
		}
		if strings.HasSuffix(interval, "h") {
			hours, err := strconv.Atoi(interval[:len(interval)-1])
			if err != nil {
				return nil, err
			}
			if hours >= 24 {
				return nil, fmt.Errorf("hours cannot be greater than or equal to 24. If specifying 24 use 'daily' instead")
			}
			iv := &api.InventoryInterval{Minutes: hours * 60}
			inventorySchedule.Interval = iv
			return inventorySchedule, nil
		}
		if strings.HasSuffix(interval, "d") {
			return nil, fmt.Errorf("days not supported please use 'm', 'daily' or 'exactly_once'")

		}
		if interval == "daily" {
			daily := &api.InventoryDaily{Time: interval}
			inventorySchedule.Daily = daily
			return inventorySchedule, nil
		}
		if interval == "exactly_once" {
			once := &api.InventoryOnce{Time: interval}
			inventorySchedule.ExactlyOnce = once
			return inventorySchedule, nil
		}
	}

	return inventorySchedule, nil
}
