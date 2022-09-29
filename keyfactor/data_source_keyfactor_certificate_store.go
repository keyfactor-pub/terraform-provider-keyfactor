package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
			"client_machine": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Client machine name; value depends on certificate store type. See API reference guide",
			},
			"store_path": {
				Type:        types.StringType,
				Computed:    true,
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
				Description: "Certificate properties specific to certificate store type configured as key-value pairs.",
			},
			"agent_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "String indicating the Keyfactor Command GUID of the orchestrator for the created store.",
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
			"password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Sets password for certificate store.",
			},
			"id": {
				Type:        types.StringType,
				Required:    true,
				Description: "Keyfactor certificate store GUID.",
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
	certificateStoreId := state.ID.Value

	tflog.SetField(ctx, "certificate_id", certificateStoreId)

	sResp, err := r.p.client.GetCertificateStoreByID(certificateStoreId)
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

	propElems := make(map[string]attr.Value)
	for k, v := range sResp.Properties {
		propElems[k] = types.String{Value: v}
	}
	var result = CertificateStore{
		ID:                    state.ID,
		ContainerID:           types.Int64{Value: int64(sResp.ContainerId)},
		ContainerName:         types.String{Value: sResp.ContainerName},
		AgentId:               types.String{Value: sResp.AgentId},
		AgentAssigned:         types.Bool{Value: sResp.AgentAssigned},
		ClientMachine:         types.String{Value: sResp.ClientMachine},
		StorePath:             types.String{Value: sResp.StorePath},
		StoreType:             types.String{Value: fmt.Sprintf("%v", sResp.CertStoreType)},
		Approved:              types.Bool{Value: sResp.Approved},
		CreateIfMissing:       types.Bool{Value: sResp.CreateIfMissing},
		Properties:            types.Map{ElemType: types.StringType, Elems: propElems},
		Password:              state.Password,
		SetNewPasswordAllowed: types.Bool{Value: sResp.SetNewPasswordAllowed},
		InventorySchedule:     state.InventorySchedule,
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
