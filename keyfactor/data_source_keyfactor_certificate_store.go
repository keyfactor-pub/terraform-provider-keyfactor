package keyfactor

import (
	"context"
	"fmt"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
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
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Client machine name; value depends on certificate store type. Required when `id` is not set. See API reference guide",
			},
			"store_path": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Path to the new certificate store on a target. Required when `id` is not set. Format varies depending on type.",
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
				Computed:    true,
				Description: "Name of the certificate store's associated container/application. Kept for backwards compatibility; prefer `application_name` for Command v25.x+.",
			},
			"application_name": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Name of the certificate store's associated application (formerly 'container'). Preferred field as of Keyfactor Command v25.x. Functionally equivalent to `container_name`.",
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
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Keyfactor certificate store GUID. When set, the store is looked up directly by GUID instead of by `client_machine` + `store_path`.",
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
		Description: "Reads an existing Keyfactor Command certificate store using the `/CertificateStores` API, which can be used for `keyfactor_certificate_deployment` resources.",
	}, nil
}

func (r dataSourceCertificateStoreType) NewDataSource(ctx context.Context, p tfsdk.Provider) (
	tfsdk.DataSource,
	diag.Diagnostics,
) {
	return dataSourceCertificateStore{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceCertificateStore struct {
	p provider
}

func (r dataSourceCertificateStore) Read(
	ctx context.Context,
	request tfsdk.ReadDataSourceRequest,
	response *tfsdk.ReadDataSourceResponse,
) {
	var state CertificateStore

	tflog.Info(ctx, "Read called on certificate resource")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate store resource")
	storeGUID := state.ID.Value
	clientMachine := state.ClientMachine.Value
	storePath := state.StorePath.Value
	containerID := state.ContainerID.Value

	var sResp *api.GetCertificateStoreResponse

	if storeGUID != "" {
		tflog.SetField(ctx, "store_id", storeGUID)
		resp, err := r.p.client.GetCertificateStoreByID(storeGUID)
		if err != nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				fmt.Sprintf("Error reading certificate store by ID '%s': %s", storeGUID, err.Error()),
			)
			return
		}
		sResp = resp
	} else {
		tflog.SetField(ctx, "client_machine", clientMachine)
		tflog.SetField(ctx, "store_path", storePath)
		if clientMachine == "" || storePath == "" {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				"Either 'id' or both 'client_machine' and 'store_path' must be specified.",
			)
			return
		}
		sRespList, err := r.p.client.GetCertificateStoreByClientAndStorePath(clientMachine, storePath, containerID)
		if err != nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				fmt.Sprintf("Error reading certificate store '%s/%s': %s", clientMachine, storePath, err.Error()),
			)
			return
		}
		if sRespList == nil || len(*sRespList) == 0 {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERT_STORE_READ,
				fmt.Sprintf("No certificate store found for client_machine '%s' and store_path '%s'", clientMachine, storePath),
			)
			return
		}
		sResp = &(*sRespList)[0]
	}

	// NOTE: a previous version of this block logged the plaintext value of
	// the store_password schema field (a declared Sensitive: true
	// attribute) at Trace level, unconditionally, on every read. There is no
	// legitimate debugging value in logging a credential by its literal
	// value, so it was removed outright rather than replaced with a
	// redacted equivalent. See TestUnitCertificateStoreDataSourcePasswordNotLogged
	// for the regression test guarding against reintroduction.

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

	// Resolve numeric store type ID to short name.
	csType, csTypeErr := r.p.client.GetCertificateStoreType(sResp.CertStoreType)
	storeTypeShortName := fmt.Sprintf("%d", sResp.CertStoreType) // fallback: numeric string
	if csTypeErr == nil && csType != nil {
		storeTypeShortName = csType.ShortName
	}

	var result = CertificateStore{
		ID:                    types.String{Value: sResp.Id},
		ContainerID:           types.Int64{Value: int64(sResp.ContainerId)},
		AgentId:               types.String{Value: sResp.AgentId},
		AgentIdentifier:       types.String{Value: sResp.AgentId},
		AgentAssigned:         types.Bool{Value: sResp.AgentAssigned},
		ClientMachine:         types.String{Value: sResp.ClientMachine},
		StorePath:             types.String{Value: sResp.StorePath},
		StoreType:             types.String{Value: storeTypeShortName},
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
	// Resolve container name via the by-ID endpoint (list endpoint is paginated).
	result.syncApplicationAndContainerName(lookupContainerNameByID(ctx, r.p.client, sResp.ContainerId, ""))

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
