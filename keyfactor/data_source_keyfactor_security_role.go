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

type dataSourceSecurityRoleType struct{}

func (r dataSourceSecurityRoleType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"role_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Internal ID of the role.",
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "An string associated with a Keyfactor security role.",
			},
			"description": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the description of the role in Keyfactor",
			},
			"permissions": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "An array containing the permissions assigned to the role in a list of Name:Value pairs",
			},
		},
	}, nil
}

func (r dataSourceSecurityRoleType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceSecurityRole{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceSecurityRole struct {
	p provider
}

func (r dataSourceSecurityRole) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	tflog.Info(ctx, "Read called on security remoteState resource")
	var state SecurityRole

	tflog.Info(ctx, "Read called on security role.")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	roleId := state.Name.Value
	tflog.SetField(ctx, "role_id", roleId)

	remoteState, err := r.p.client.GetSecurityRole(roleId)
	if remoteState == nil {
		response.Diagnostics.AddError("Unknown role error.", fmt.Sprintf("Unable to find role '%v' on Keyfactor. Read failed. ", roleId))
		return
	}

	if err != nil {
		response.Diagnostics.AddError("Unknown role error.", fmt.Sprintf("Unknown error while trying to import role '%v' on Keyfactor. Read failed. "+err.Error(), roleId))
		return
	}

	var permissionValues []attr.Value
	for _, perm := range remoteState.Permissions {
		tflog.Debug(ctx, fmt.Sprintf("Permission: %v", perm))
		permissionValues = append(permissionValues, types.String{Value: perm})
	}

	var result = SecurityRole{
		ID:          types.Int64{Value: int64(remoteState.Id)},
		Name:        types.String{Value: remoteState.Name},
		Description: types.String{Value: remoteState.Description},
		Permissions: types.List{ElemType: types.StringType, Elems: permissionValues},
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	if response.Diagnostics.HasError() {
		return
	}
}
