package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourcePAMProviderType struct{}

func (d dataSourcePAMProviderType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Name or integer ID of the PAM provider to look up.",
			},
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Integer ID of the PAM provider.",
			},
			"name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Name of the PAM provider.",
			},
			"provider_type_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "GUID of the PAM provider type.",
			},
			"provider_type_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Name of the PAM provider type.",
			},
			"remote": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether the PAM provider runs remotely.",
			},
			"area": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Area (zone) integer identifier for this PAM provider.",
			},
		},
		Description: "Reads an existing Keyfactor Command PAM Provider by name or integer ID. Parameter values are not exposed because secret values cannot be recovered from the server.",
	}, nil
}

func (d dataSourcePAMProviderType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourcePAMProvider{
		p: *(p.(*provider)),
	}, nil
}

type dataSourcePAMProvider struct {
	p provider
}

// KeyfactorPAMProviderDataSource is the Terraform state model for data.keyfactor_pam_provider.
type KeyfactorPAMProviderDataSource struct {
	Identifier       types.String `tfsdk:"identifier"`
	ID               types.Int64  `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	ProviderTypeID   types.String `tfsdk:"provider_type_id"`
	ProviderTypeName types.String `tfsdk:"provider_type_name"`
	Remote           types.Bool   `tfsdk:"remote"`
	Area             types.Int64  `tfsdk:"area"`
}

func pamProviderResponseToDataSource(identifier string, resp *v1.PAMProviderResponseLegacy) KeyfactorPAMProviderDataSource {
	ds := KeyfactorPAMProviderDataSource{
		Identifier: types.String{Value: identifier},
		ID:         types.Int64{Value: int64(resp.GetId())},
		Name:       types.String{Value: resp.GetName()},
		Remote:     types.Bool{Value: resp.GetRemote()},
		Area:       types.Int64{Value: int64(resp.GetArea())},
	}
	if resp.ProviderType != nil {
		ds.ProviderTypeID = types.String{Value: resp.ProviderType.GetId()}
		ds.ProviderTypeName = types.String{Value: resp.ProviderType.GetName()}
	}
	return ds
}

func (d dataSourcePAMProvider) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	LogFunctionEntry(ctx, "dataSourcePAMProvider.Read")

	var state KeyfactorPAMProviderDataSource
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	identifier := state.Identifier.Value
	tflog.Info(ctx, fmt.Sprintf("Reading PAM provider with identifier %q", identifier))

	pamAPI := d.p.sdkClient.V1.PAMProviderApi

	// Try to parse as integer ID first, then fall back to name lookup.
	if numericID, err := strconv.Atoi(identifier); err == nil {
		req := pamAPI.NewGetPamProvidersByIdRequest(ctx, int32(numericID))
		resp, httpResp, err := req.Execute()
		if err != nil {
			body := readHTTPResponseBody(httpResp)
			response.Diagnostics.AddError(
				"Error reading PAM provider.",
				fmt.Sprintf("Could not read PAM provider with ID %d: %s. Details: %s", numericID, err.Error(), body),
			)
			return
		}
		result := pamProviderResponseToDataSource(identifier, resp)
		diags = response.State.Set(ctx, &result)
		response.Diagnostics.Append(diags...)
		LogFunctionExit(ctx, "dataSourcePAMProvider.Read")
		return
	}

	// Name lookup: list all providers and find by name.
	listReq := pamAPI.NewGetPamProvidersRequest(ctx)
	allProviders, httpResp, err := listReq.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error listing PAM providers.",
			fmt.Sprintf("Could not list PAM providers: %s. Details: %s", err.Error(), body),
		)
		return
	}

	for _, prov := range allProviders {
		if prov.GetName() == identifier {
			result := pamProviderResponseToDataSource(identifier, &prov)
			diags = response.State.Set(ctx, &result)
			response.Diagnostics.Append(diags...)
			LogFunctionExit(ctx, "dataSourcePAMProvider.Read")
			return
		}
	}

	response.Diagnostics.AddError(
		"PAM provider not found.",
		fmt.Sprintf("No PAM provider matching %q was found in Keyfactor Command.", identifier),
	)
	LogFunctionExit(ctx, "dataSourcePAMProvider.Read")
}
