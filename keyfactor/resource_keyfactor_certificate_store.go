package keyfactor

import (
	"context"
	"encoding/json"
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
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Keyfactor Command certificate store GUID.",
			},
			"container_id": {
				Type: types.Int64Type,
				//Optional: true,
				Computed:    true,
				Description: "Container identifier of the store's associated certificate store container.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"display_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Display name of the certificate store. Is the concatenation of 'ClientMachine - StorePath'.",
			},
			"client_machine": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Client machine name; value depends on certificate store type. See API reference guide and/or store type documentation.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"store_path": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Path to the new certificate store on a target. Format varies depending on store type see the store type documentation for more information.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"store_type": {
				Type:          types.StringType,
				Required:      true,
				Description:   "Short name of certificate store type.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"approved": {
				Type: types.BoolType,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
				Description: "Bool that indicates the approval status of store. Unapproved stores come from store Discovery and cannot be used for certificate operations.",
				Computed:    true,
				//PlanModifiers:       []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"create_if_missing": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Determines whether the store create job will be scheduled. WARNING: If set to TRUE, each apply will trigger a store create job, if the store type support Create. This may cause issues if the store already exists but will depend on the store type.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"properties": {
				Type:        types.MapType{ElemType: types.StringType},
				Optional:    true,
				Description: "Certificate properties specific to certificate store type configured as key-value pairs. NOTE: Special properties 'ServerUsername' and 'ServerPassword' are required for some store types and should not be declared in this attribute and have their own dedicated values. See store type documentation for more information.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"agent_identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Can be either ClientMachine or the Keyfactor Command GUID of the orchestrator to use for managing the certificate store. The agent must support the certificate store type and be approved.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"agent_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "String indicating the Keyfactor Command GUID of the orchestrator for the created store.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"agent_assigned": {
				Type:     types.BoolType,
				Computed: true,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
				Description: "Bool indicating if there is an orchestrator assigned to the new certificate store.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"container_name": {
				Type:     types.StringType,
				Optional: true,
				//Computed:    true,
				Description: "Name of the container you want to associate the certificate store with. NOTE: The container must already exist and be of the same certificate store type.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
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
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"set_new_password_allowed": {
				Type: types.BoolType,
				//Optional:    true,
				Computed:    true,
				Description: "Indicates whether the store password can be changed.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"store_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "The password to access the contents of the certificate store. In Keyfactor Command this is the 'StorePassword' field. field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"server_username": {
				Type:        types.StringType,
				Optional:    true,
				Description: "The username to access the host of the certificate store. In Keyfactor Command this is the 'ServerUsername' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
			"server_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "The password to access the host of the certificate store. In Keyfactor Command this is the 'ServerUsername' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
			"server_use_ssl": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Indicates whether the certificate store host requires SSL. In Keyfactor Command this is the 'ServerUseSsl' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
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

	containerId := 0
	if !plan.ContainerName.IsNull() {
		storeContainer, containerErr := r.p.client.GetStoreContainer(plan.ContainerName.Value)
		if containerErr != nil || storeContainer == nil {
			response.Diagnostics.AddError(
				"Invalid container name.",
				fmt.Sprintf("Could not retrieve container '%s' from Keyfactor"+containerErr.Error(), plan.ContainerName.Value),
			)
			return
		}
		containerId = *storeContainer.Id
	}

	var properties map[string]string
	if plan.Properties.Elems != nil {
		diags = plan.Properties.ElementsAs(ctx, &properties, false)
	}
	//Add Special Properties to properties map
	if !plan.ServerUsername.IsNull() {
		properties["ServerUsername"] = plan.ServerUsername.Value
	}
	if !plan.ServerPassword.IsNull() {
		properties["ServerPassword"] = plan.ServerPassword.Value
	}
	if !plan.ServerUseSsl.IsNull() {
		properties["ServerUseSsl"] = strconv.FormatBool(plan.ServerUseSsl.Value)
	}

	schedule, err := createInventorySchedule(plan.InventorySchedule.Value) // TODO: Implement inventory schedule
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid inventory schedule.",
			fmt.Sprintf("Could not create inventory schedule: %s", err.Error()),
		)
		return
	}

	var storePassFormatted *api.StorePasswordConfig
	if plan.StorePassword.Null {
		storePassFormatted = nil
	} else {
		storePassFormatted = createPasswordConfig(plan.StorePassword.Value)
	}

	//Lookup agent by AgentIdentifier
	agents, agentErr := kfClient.GetAgent(plan.AgentIdentifier.Value)
	agentId := ""
	//TODO: Make this a function
	if agentErr != nil {
		response.Diagnostics.AddError(
			"Invalid agent identifier.",
			fmt.Sprintf("Agent could not be found on Keyfactor Command using identifier '%s'. %s", plan.AgentIdentifier.Value, agentErr.Error()),
		)
		return
	} else if len(agents) == 0 {
		response.Diagnostics.AddError(
			"Agent Not Found.",
			fmt.Sprintf("Agent could not be found on Keyfactor Command using identifier '%s'. %s", plan.AgentIdentifier.Value, agentErr.Error()),
		)
		return
	} else {
		if len(agents) > 1 {
			response.Diagnostics.AddWarning(
				"Agent Not Found.",
				fmt.Sprintf("Multiple agents found with identifier '%s' returned from Keyfactor Command. Using first approved agent", plan.AgentIdentifier.Value),
			)
		}

		//iterate over agents and find the first approved agent
		for _, agent := range agents {
			if agent.Status != 2 {
				continue
			}
			agentId = agent.AgentId
			break
		}

		if agentId == "" {
			response.Diagnostics.AddError(
				"Approved Agent Not Found.",
				fmt.Sprintf("No approved agents with identifier '%s' were found on Keyfactor Command. Please review your agents on the Keyfactor Command Portal by going to Orchestrators > Management, and ensure the one you're looking for is approved.", plan.AgentIdentifier.Value),
			)
			return
		}

		tflog.Debug(ctx, fmt.Sprintf("Agent: %s", agentId))
	}

	//if plan.CreateIfMissing.IsNull() {
	//	plan.CreateIfMissing = types.Bool{Value: false}
	//}

	newStoreArgs := &api.CreateStoreFctArgs{
		ContainerId:           intToPointer(containerId),
		ClientMachine:         plan.ClientMachine.Value,
		StorePath:             plan.StorePath.Value,
		CertStoreType:         csType.StoreType,
		Approved:              &plan.Approved.Value,
		CreateIfMissing:       &plan.CreateIfMissing.Value,
		Properties:            properties,
		AgentId:               agentId,
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
		StoreType:             plan.StoreType,
		Approved:              types.Bool{Value: createStoreResponse.Approved},
		CreateIfMissing:       plan.CreateIfMissing,
		Properties:            plan.Properties,
		AgentId:               types.String{Value: createStoreResponse.AgentId},
		AgentIdentifier:       plan.AgentIdentifier,
		AgentAssigned:         types.Bool{Value: createStoreResponse.AgentAssigned},
		ContainerName:         plan.ContainerName,
		InventorySchedule:     plan.InventorySchedule,
		SetNewPasswordAllowed: types.Bool{Value: createStoreResponse.SetNewPasswordAllowed},
		StorePassword:         plan.StorePassword,
		ServerUsername:        plan.ServerUsername,
		ServerPassword:        plan.ServerPassword,
		ServerUseSsl:          plan.ServerUseSsl,
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

	sResp, err := r.p.client.GetCertificateStoreByID(certificateStoreId)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading certificate store",
			fmt.Sprintf("Error reading certificate store: '%s'. %s", certificateStoreId, err.Error()),
		)
		return
	}

	var result = CertificateStore{
		ID: types.String{Value: sResp.Id},
		ContainerID: types.Int64{
			Null:  state.ContainerID.Null,
			Value: int64(sResp.ContainerId),
		},
		ClientMachine:         types.String{Value: sResp.ClientMachine},
		StorePath:             types.String{Value: sResp.StorePath},
		StoreType:             state.StoreType,
		Approved:              types.Bool{Value: sResp.Approved},
		CreateIfMissing:       state.CreateIfMissing,
		Properties:            state.Properties, //TODO: Parse this w/o special properties included
		AgentId:               types.String{Value: sResp.AgentId},
		AgentIdentifier:       state.AgentIdentifier,
		AgentAssigned:         types.Bool{Value: sResp.AgentAssigned},
		ContainerName:         types.String{Value: sResp.ContainerName},
		InventorySchedule:     state.InventorySchedule, // TODO: Parse this from sResp.InventorySchedule
		SetNewPasswordAllowed: types.Bool{Value: sResp.SetNewPasswordAllowed},
		StorePassword:         state.StorePassword,  //TODO: Currently command doesn't return this as of 10.x
		ServerUsername:        state.ServerUsername, //TODO: Parse this from sResp.Properties
		ServerPassword:        state.ServerPassword, //TODO: Parse this from sResp.Properties
		ServerUseSsl:          state.ServerUseSsl,   //TODO: Parse this from sResp.Properties
		//Certificates:          types.List{ElemType: types.Int64Type, Elems: []attr.Value{}},
	}

	// Set state
	diags = response.State.Set(ctx, &result)
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

	// Generate API request body from plan
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

	containerId := 0
	if !plan.ContainerName.IsNull() {
		storeContainer, containerErr := r.p.client.GetStoreContainer(plan.ContainerName.Value)
		if containerErr != nil || storeContainer == nil {
			response.Diagnostics.AddError(
				"Invalid container name.",
				fmt.Sprintf("Could not retrieve container '%s' from Keyfactor"+containerErr.Error(), plan.ContainerName.Value),
			)
			return
		}
		containerId = *storeContainer.Id
	}

	storePassFormatted := createPasswordConfig(plan.StorePassword.Value)

	agents, agentErr := r.p.client.GetAgent(plan.AgentIdentifier.Value)
	agentId := ""
	//TODO: Make this a function
	if agentErr != nil {
		response.Diagnostics.AddError(
			"Invalid agent identifier.",
			fmt.Sprintf("Agent could not be found on Keyfactor Command using identifier '%s'. %s", plan.AgentIdentifier.Value, agentErr.Error()),
		)
		return
	} else if len(agents) == 0 {
		response.Diagnostics.AddError(
			"Agent Not Found.",
			fmt.Sprintf("Agent could not be found on Keyfactor Command using identifier '%s'. %s", plan.AgentIdentifier.Value, agentErr.Error()),
		)
		return
	} else {
		if len(agents) > 1 {
			response.Diagnostics.AddWarning(
				"Agent Not Found.",
				fmt.Sprintf("Multiple agents found with identifier '%s' returned from Keyfactor Command. Using first approved agent", plan.AgentIdentifier.Value),
			)
		}

		//iterate over agents and find the first approved agent
		for _, agent := range agents {
			if agent.Status != 2 {
				continue
			}
			agentId = agent.AgentId
			break
		}

		if agentId == "" {
			response.Diagnostics.AddError(
				"Approved Agent Not Found.",
				fmt.Sprintf("No approved agents with identifier '%s' were found on Keyfactor Command. Please review your agents on the Keyfactor Command Portal by going to Orchestrators > Management, and ensure the one you're looking for is approved.", plan.AgentIdentifier.Value),
			)
			return
		}

		tflog.Debug(ctx, fmt.Sprintf("Agent: %s", agentId))
	}

	var properties map[string]interface{}
	if plan.Properties.Elems != nil {
		diags = plan.Properties.ElementsAs(ctx, &properties, false)
	}
	//Add Special Properties to properties map
	if !plan.ServerUsername.IsNull() {
		formattedUsername := api.SecretParamValue{SecretValue: plan.ServerUsername.Value}
		properties["ServerUsername"] = api.SpecialPropertiesSecretValue{Value: formattedUsername}
	}
	if !plan.ServerPassword.IsNull() {
		formattedPassword := api.SecretParamValue{SecretValue: plan.ServerPassword.Value}
		properties["ServerPassword"] = api.SpecialPropertiesSecretValue{Value: formattedPassword}
	}
	if !plan.ServerUseSsl.IsNull() {
		properties["ServerUseSsl"] = api.SpecialPropertiesValue{Value: plan.ServerUseSsl.Value}
	}

	propertiesStr, psErr := mapToEscapedJSONString(properties)
	if psErr != nil {
		response.Diagnostics.AddError(
			"Invalid properties error.",
			fmt.Sprintf("Invalid properties for certificate store updating certificate store: %s", psErr.Error()),
		)
		return
	}

	updateStoreArgs := &api.UpdateStoreFctArgs{
		Id:                    state.ID.Value,
		ContainerId:           intToPointer(containerId),
		ClientMachine:         plan.ClientMachine.Value,
		StorePath:             plan.StorePath.Value,
		CertStoreType:         csType.StoreType,
		Approved:              &plan.Approved.Value,
		CreateIfMissing:       &plan.CreateIfMissing.Value,
		Properties:            properties,
		PropertiesString:      propertiesStr,
		AgentId:               agentId,
		AgentAssigned:         &plan.AgentAssigned.Value,
		ContainerName:         &plan.ContainerName.Value,
		InventorySchedule:     schedule,
		SetNewPasswordAllowed: &plan.SetNewPasswordAllowed.Value,
		Password:              storePassFormatted,
	}

	// log updatestore args as json
	tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %s", updateStoreArgs))
	// convert updatestore args to json string
	updateStoreArgsJson, err := json.Marshal(updateStoreArgs)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate store configuration error.",
			fmt.Sprintf("Invalid configuration for certificate store: %s", err.Error()),
		)
		return
	}
	// log updatestore args as json string
	tflog.Debug(ctx, fmt.Sprintf("UpdateStoreFctArgs: %s", updateStoreArgsJson))
	updateResponse, err := r.p.client.UpdateStore(updateStoreArgs)
	if err != nil {
		response.Diagnostics.AddError(
			"Error updating certificate store",
			"Error updating certificate store: %s"+err.Error(),
		)
		return
	}

	// Log response
	tflog.Trace(ctx, fmt.Sprintf("UpdateStoreResponse: %s", updateResponse))

	result := CertificateStore{
		ID: types.String{Value: updateResponse.Id},
		ContainerID: types.Int64{
			Null:  plan.ContainerID.Null,
			Value: int64(updateResponse.ContainerId),
		},
		ClientMachine:         types.String{Value: updateResponse.ClientMachine},
		StorePath:             types.String{Value: updateResponse.Storepath},
		StoreType:             plan.StoreType,
		Approved:              types.Bool{Value: updateResponse.Approved},
		CreateIfMissing:       plan.CreateIfMissing,
		Properties:            plan.Properties,
		AgentId:               types.String{Value: updateResponse.AgentId},
		AgentIdentifier:       plan.AgentIdentifier,
		AgentAssigned:         types.Bool{Value: updateResponse.AgentAssigned},
		ContainerName:         plan.ContainerName,
		InventorySchedule:     plan.InventorySchedule,
		SetNewPasswordAllowed: types.Bool{Value: updateResponse.SetNewPasswordAllowed},
		StorePassword:         plan.StorePassword,
		ServerUsername:        plan.ServerUsername,
		ServerPassword:        plan.ServerPassword,
		ServerUseSsl:          plan.ServerUseSsl,
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

	password := state.StorePassword.Value
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
		//Password:              plan.StorePassword,
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

func parseInventorySchedule(schedule *api.InventorySchedule) string {
	if schedule.Immediate != nil {
		return "immediate"
	}
	if schedule.Interval != nil {
		return fmt.Sprintf("%vm", schedule.Interval.Minutes)
	}
	if schedule.Daily != nil {
		return fmt.Sprintf("Daily at %s", schedule.Daily.Time)
	}
	if schedule.ExactlyOnce != nil {
		return fmt.Sprintf("Exactly once at %s", schedule.ExactlyOnce.Time)
	}

	return ""
}

func buildPropertiesInterface(properties *map[string]string) map[string]interface{} {
	// Create temporary array of interfaces
	// When updating a property in Keyfactor, API expects {"key": {"value": "key-value"}} - Build this interface
	propertiesInterface := make(map[string]interface{})

	creds := CertificateStoreCredential{
		ServerUsername: struct {
			Value struct {
				SecretValue string `json:"SecretValue"`
			} `json:"value"`
		}{},
		ServerPassword: struct {
			Value struct {
				SecretValue string `json:"SecretValue"`
			} `json:"value"`
		}{},
		ServerUseSsl: struct {
			Value string `json:"value"`
		}{},
	}

	for key, value := range *properties {
		if key == "ServerUsername" || key == "ServerPassword" || key == "Password" {
			if key == "ServerUsername" {
				creds.ServerUsername.Value.SecretValue = value
				// add to propertiesInterface as JSON string
				//jsonBytes, _ := json.Marshal(creds.ServerUsername)
				propertiesInterface[key] = creds.ServerUsername
			}
			if key == "ServerPassword" || key == "Password" {
				creds.ServerPassword.Value.SecretValue = value
				//jsonBytes, _ := json.Marshal(creds.ServerPassword)
				propertiesInterface[key] = creds.ServerPassword
			}
		} else {
			propertiesInterface[key] = value // Create {"<key>": {"value": "key-value"}} interface
		}
	}
	return propertiesInterface
}

func mapToEscapedJSONString(m map[string]interface{}) (string, error) {
	// Convert the map to a byte slice of JSON
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	// Escape any special characters in the JSON string
	escapedString := string(jsonBytes)

	return escapedString, nil
}
