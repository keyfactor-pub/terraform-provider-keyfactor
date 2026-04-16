package keyfactor

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourcePAMProviderTypeType struct{}

func (d dataSourcePAMProviderTypeType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Name or GUID of the PAM provider type to look up.",
			},
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "GUID identifier of the PAM provider type.",
			},
			"name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Name of the PAM provider type.",
			},
			"parameters": {
				Computed:    true,
				Description: "Parameters defined for this PAM provider type.",
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"id": {
						Type:        types.Int64Type,
						Computed:    true,
						Description: "Integer ID of the parameter.",
					},
					"name": {
						Type:        types.StringType,
						Computed:    true,
						Description: "Parameter name.",
					},
					"display_name": {
						Type:        types.StringType,
						Computed:    true,
						Description: "Human-readable display name for the parameter.",
					},
					"data_type": {
						Type:        types.Int64Type,
						Computed:    true,
						Description: "Data type of the parameter: 1 = string, 2 = secret.",
					},
					"instance_level": {
						Type:        types.BoolType,
						Computed:    true,
						Description: "Whether this parameter is configured at the instance level.",
					},
				}),
			},
		},
		Description: "Reads an existing Keyfactor Command PAM Provider Type by name or GUID.",
	}, nil
}

func (d dataSourcePAMProviderTypeType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourcePAMProviderTypeImpl{
		p: *(p.(*provider)),
	}, nil
}

type dataSourcePAMProviderTypeImpl struct {
	p provider
}

// KeyfactorPAMProviderTypeDataSource is the Terraform state model for data.keyfactor_pam_provider_type.
type KeyfactorPAMProviderTypeDataSource struct {
	Identifier types.String                    `tfsdk:"identifier"`
	ID         types.String                    `tfsdk:"id"`
	Name       types.String                    `tfsdk:"name"`
	Parameters []KeyfactorPAMProviderTypeParam `tfsdk:"parameters"`
}

func (d dataSourcePAMProviderTypeImpl) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	LogFunctionEntry(ctx, "dataSourcePAMProviderType.Read")

	var state KeyfactorPAMProviderTypeDataSource
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	identifier := state.Identifier.Value
	tflog.Info(ctx, fmt.Sprintf("Reading PAM provider type with identifier %q", identifier))

	pamAPI := d.p.sdkClient.V1.PAMProviderApi
	req := pamAPI.NewGetPamProvidersTypesRequest(ctx)
	allTypes, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error listing PAM provider types.",
			fmt.Sprintf("Could not list PAM provider types: %s. Details: %s", err.Error(), body),
		)
		return
	}

	// Match by GUID (case-insensitive) or by name (exact).
	for _, pt := range allTypes {
		if strings.EqualFold(pt.GetId(), identifier) || pt.GetName() == identifier {
			result := KeyfactorPAMProviderTypeDataSource{
				Identifier: state.Identifier,
			}
			typeState := pamProviderTypeResponseToState(&pt)
			result.ID = typeState.ID
			result.Name = typeState.Name
			result.Parameters = typeState.Parameters

			diags = response.State.Set(ctx, &result)
			response.Diagnostics.Append(diags...)
			LogFunctionExit(ctx, "dataSourcePAMProviderType.Read")
			return
		}
	}

	response.Diagnostics.AddError(
		"PAM provider type not found.",
		fmt.Sprintf("No PAM provider type matching %q was found in Keyfactor Command.", identifier),
	)
	LogFunctionExit(ctx, "dataSourcePAMProviderType.Read")
}
