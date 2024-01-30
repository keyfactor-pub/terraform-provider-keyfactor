package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceCertificateStoreType struct{}

func (r dataSourceCertificateStoreType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"container_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Container identifier of the store's associated certificate store container.",
			},
			"display_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Display name of the certificate store.",
			},
			"client_machine": {
				Type: types.StringType,
				//Computed:    true,
				Required:    true,
				Description: "Client machine name; value depends on certificate store type. See API reference guide",
			},
			"store_path": {
				Type: types.StringType,
				//Computed:    true,
				Required:    true,
				Description: "Path to the new certificate store on a target. Format varies depending on type.",
			},
			"store_type": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Short name of certificate store type. See API reference guide",
			},
			"approved": {
				Type:     types.BoolType,
				Optional: true,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
				Description: "Bool that indicates the approval status of store created. Default is true, omit if unsure.",
			},
			"create_if_missing": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Bool that indicates if the store should be created with information provided. Valid only for JKS type, omit if unsure.",
			},
			"properties": {
				Type:        types.MapType{ElemType: types.StringType},
				Optional:    true,
				Description: "Properties specific to certificate store type configured as key-value pairs.",
			},
			"agent_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "String indicating the Keyfactor Command GUID of the orchestrator for the created store.",
			},
			"agent_identifier": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Can be either ClientMachine or the Keyfactor Command GUID of the orchestrator to use for managing the certificate store. The agent must support the certificate store type and be approved.",
			},
			"agent_assigned": {
				Type:     types.BoolType,
				Optional: true,
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
				Description: "Bool indicating if there is an orchestrator assigned to the new certificate store.",
			},
			"container_name": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Name of certificate store's associated container, if applicable.",
			},
			"inventory_schedule": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Inventory schedule for new certificate store.",
			},
			"set_new_password_allowed": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "Indicates whether the store password can be changed.",
			},
			"id": {
				Type: types.StringType,
				//Required:    true,
				Computed:    true,
				Description: "Keyfactor certificate store GUID.",
			},
			"store_password": {
				Type:        types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "The password to access the contents of the certificate store. In Keyfactor Command this is the 'StorePassword' field. field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"server_username": {
				Type:        types.StringType,
				Computed:    true,
				Description: "The username to access the host of the certificate store. In Keyfactor Command this is the 'ServerUsername' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
			"server_password": {
				Type:        types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "The password to access the host of the certificate store. In Keyfactor Command this is the 'ServerUsername' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
			"server_use_ssl": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Indicates whether the certificate store host requires SSL. In Keyfactor Command this is the 'ServerUseSsl' field found in the store type 'Properties'. Whether this is required and what format will vary based on store type definitions, please review the store type documentation for more information.",
			},
		},
	}, nil
}

func (r dataSourceCertificateStoreType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertificateStore{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceCertificateStore struct {
	p provider
}

func (r dataSourceCertificateStore) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	var state CertificateStore

	tflog.Info(ctx, "Read called on certificate resource")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate store resource")
	//certificateStoreID := state.ID.Value
	clientMachine := state.ClientMachine.Value
	storePath := state.StorePath.Value
	containerID := state.ContainerID.Value

	//tflog.SetField(ctx, "certificate_id", certificateStoreID)
	tflog.SetField(ctx, "client_machine", clientMachine)
	tflog.SetField(ctx, "store_path", storePath)

	//sResp, err := r.p.client.GetCertificateStoreByID(certificateStoreID)
	sRespList, err := r.p.client.GetCertificateStoreByClientAndStorePath(clientMachine, storePath, containerID)
	if err != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERT_STORE_READ,
			"Error reading certificate store: %s"+err.Error(),
		)
		return
	}

	if sRespList != nil && len(*sRespList) == 0 {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERT_STORE_READ,
			fmt.Sprintf("Error reading certificate store '%s/%s'", clientMachine, storePath),
		)
		return
	}
	sRespRef := *sRespList
	//Because we're looking up by client machine and store path, there should only be one result as that's what Command uses for uniqueness as of KF 9.x
	sResp := sRespRef[0]

	password := state.StorePassword.Value
	tflog.Trace(ctx, fmt.Sprintf("Password for store %s: %s", sResp.Id, password))

	if err != nil {
		response.Diagnostics.AddError(
			"Certificate store not found",
			fmt.Sprintf("Unable to locate certificate store using client machine '%s' and storepath '%s' %s", clientMachine, storePath, err.Error()),
		)
		return
	}

	// parse inventory schedule
	invSchedule := parseInventorySchedule(&sResp.InventorySchedule)
	// parse store password
	storePassword := parseStorePassword(&sResp.Password)
	// parse properties
	properties, serverUsername, serverPassword, serverUseSsl, propDiags := parseProperties(sResp.PropertiesString)
	if propDiags.HasError() {
		response.Diagnostics.Append(propDiags...)
		return
	}

	var result = CertificateStore{
		ID:                    types.String{Value: sResp.Id},
		ContainerID:           types.Int64{Value: int64(sResp.ContainerId)},
		ContainerName:         types.String{Value: sResp.ContainerName},
		AgentId:               types.String{Value: sResp.AgentId},
		AgentIdentifier:       types.String{Value: sResp.AgentId},
		AgentAssigned:         types.Bool{Value: sResp.AgentAssigned},
		ClientMachine:         state.ClientMachine,
		StorePath:             state.StorePath,
		StoreType:             types.String{Value: fmt.Sprintf("%v", sResp.CertStoreType)},
		Approved:              types.Bool{Value: sResp.Approved},
		CreateIfMissing:       types.Bool{Value: sResp.CreateIfMissing},
		Properties:            properties,
		SetNewPasswordAllowed: types.Bool{Value: sResp.SetNewPasswordAllowed},
		InventorySchedule:     types.String{Value: invSchedule},
		ServerUsername:        serverUsername,
		ServerPassword:        serverPassword,
		ServerUseSsl:          serverUseSsl,
		StorePassword:         storePassword,
		DisplayName:           types.String{Value: sResp.DisplayName},
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
