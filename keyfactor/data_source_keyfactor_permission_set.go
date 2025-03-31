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

type dataSourcePermissionSetType struct{}

func (r dataSourcePermissionSetType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Internal ID of the permission set",
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Name of the permission set",
			},
			"permissions": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "A list of permissions associated with the permission set",
			},
		},
	}, nil
}

func (r dataSourcePermissionSetType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourcePermissionSet{
		p: *(p.(*provider)),
	}, nil
}

type dataSourcePermissionSet struct {
	p provider
}

func (r dataSourcePermissionSet) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	tflog.Info(ctx, "Read called on permission set remoteState resource")
	var state PermissionSet

	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	permissionSetName := state.Name.Value
	permissionSet, err := GetSecurityPermissionSetByName(ctx, r.p.sdkClient, permissionSetName)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading permission set",
			"Unable to find permission set with name: "+permissionSetName+". Error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Permission set read successfully from source. ID: %s", *permissionSet.Id))

	var permissionValues []attr.Value
	for _, perm := range permissionSet.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		permissionValues = append(permissionValues, types.String{Value: perm})
	}

	result := PermissionSet{
		ID:          types.String{Value: *permissionSet.Id},
		Name:        types.String{Value: *permissionSet.Name.Get()},
		Permissions: types.List{ElemType: types.StringType, Elems: permissionValues},
	}

	tflog.Debug(ctx, "Saving permission set data source information into state...")

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Permission source data source read successfully.")
}
