package keyfactor

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceOAuthSecurityRoleType struct{}

func (r dataSourceOAuthSecurityRoleType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Internal ID of the role.",
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Description of the security role",
			},
			"description": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the description of the OAuth security claim in Keyfactor",
			},
			"email_address": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Email address associated with the OAuth security role in Keyfactor",
			},
			"immutable": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Indicates whether the OAuth security role in Keyfactor is immutable. If true, the role cannot be modified or deleted. This is typically used for system-defined roles that are essential for the operation of Keyfactor.",
			},
			"permission_set_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "The ID of the permission set associated with the OAuth security role in Keyfactor. This is used to identify the permissions associated with the role.",
			},
			"permissions": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "A list of permissions associated with the OAuth security role in Keyfactor. This will return a list of permissions that are associated with the OAuth security role. This is used to identify the permissions associated with the role.",
			},
		},
		Description: "Reads an existing security role from Keyfactor Command using the V2 `/Security/Roles` API. Compatible with Keyfactor Command versions 11+.",
	}, nil
}

func (r dataSourceOAuthSecurityRoleType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceOauthSecurityRole{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceOauthSecurityRole struct {
	p provider
}

func (r dataSourceOauthSecurityRole) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	tflog.Info(ctx, "Read called on OAuth security role data source.")

	data, ok := getDataSource[OAuthSecurityRole](ctx, &request.Config, &response.Diagnostics)
	if !ok {
		return
	}

	roleName := data.Name.Value
	role, err := getSecurityRoleByName(ctx, r.p.sdkClient, roleName)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading OAuth security role",
			"Unable to find OAuth security role with name: "+roleName+". Error: "+err.Error(),
		)
		return
	}

	roleId := int32(*role.Id)

	tflog.Debug(ctx, "Data source was able to identify OAuth security role from remote source")
	tflog.Debug(ctx, fmt.Sprintf("Querying security role by ID %d", roleId))

	api := r.p.sdkClient.V2.SecurityRolesApi
	remoteState, httpReq, err := api.NewGetSecurityRolesByIdRequest(ctx, int32(*role.Id)).Execute()
	if err != nil {
		defer httpReq.Body.Close()
		body, _ := io.ReadAll(httpReq.Body)

		response.Diagnostics.AddError(
			"Error reading security role",
			fmt.Sprintf("Could not read OAuth security role %s , unexpected error: %s. Details %s ", roleName, err.Error(), string(body)),
		)
		return
	}

	tflog.Debug(ctx, "Data source was able to resource OAuth security role from remote source using ID")

	var result = mapOAuthSecurityRole(ctx, remoteState)

	tflog.Debug(ctx, "Saving OAuth security role data source information into state...")

	ok = updateState(ctx, &response.State, &response.Diagnostics, result)
	if !ok {
		return
	}

	tflog.Debug(ctx, "OAuth security role data source read successfully.")
}
