package keyfactor

import (
	"context"
	"fmt"
	"net/http"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceCertificateCollectionType struct{}

func (d dataSourceCertificateCollectionType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"name": {
				Type:        types.StringType,
				Optional:    true,
				Description: "The name of the certificate collection to look up. Either `name` or `id` must be provided.",
			},
			"id": {
				Type:        types.Int64Type,
				Optional:    true,
				Computed:    true,
				Description: "The internal Keyfactor Command identifier of the certificate collection to look up. Either `name` or `id` must be provided.",
			},
			"description": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A description of the certificate collection.",
			},
			"content": {
				Type:        types.StringType,
				Computed:    true,
				Description: "The query string that defines the certificate collection.",
			},
			"duplication_field": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating how duplicate certificate subjects are determined for the certificate collection.",
			},
			"show_on_dashboard": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether the certificate collection is shown on the Keyfactor Command dashboard.",
			},
			"favorite": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether the certificate collection is marked as a favorite.",
			},
			"estimated_cert_count": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "The estimated number of certificates that match the certificate collection query.",
			},
			"last_estimated": {
				Type:        types.StringType,
				Computed:    true,
				Description: "The timestamp of the last time the estimated certificate count was calculated.",
			},
		},
		Description: "Reads an existing Keyfactor Command certificate collection by name or ID.",
	}, nil
}

func (d dataSourceCertificateCollectionType) NewDataSource(_ context.Context, p tfsdk.Provider) (
	tfsdk.DataSource,
	diag.Diagnostics,
) {
	return dataSourceCertificateCollection{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceCertificateCollection struct {
	p provider
}

// CertificateCollectionDataSourceState is the Terraform state model for data.keyfactor_certificate_collection.
type CertificateCollectionDataSourceState struct {
	ID                 types.Int64  `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Content            types.String `tfsdk:"content"`
	DuplicationField   types.Int64  `tfsdk:"duplication_field"`
	ShowOnDashboard    types.Bool   `tfsdk:"show_on_dashboard"`
	Favorite           types.Bool   `tfsdk:"favorite"`
	EstimatedCertCount types.Int64  `tfsdk:"estimated_cert_count"`
	LastEstimated      types.String `tfsdk:"last_estimated"`
}

func (d dataSourceCertificateCollection) Read(
	ctx context.Context,
	request tfsdk.ReadDataSourceRequest,
	response *tfsdk.ReadDataSourceResponse,
) {
	LogFunctionEntry(ctx, "DataSourceCertificateCollection_Read")

	var state CertificateCollectionDataSourceState
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	idSet := !state.ID.Null && !state.ID.Unknown
	nameSet := !state.Name.Null && !state.Name.Unknown
	if !idSet && !nameSet {
		response.Diagnostics.AddError(
			"Missing required lookup attribute.",
			"Either 'name' or 'id' must be set to look up a certificate collection.",
		)
		return
	}

	collectionApi := d.p.sdkClient.V1.CertificateCollectionApi

	var resp *v1.CSSCMSDataModelModelsCertificateQuery
	var httpResp *http.Response
	var err error

	if idSet {
		tflog.Debug(ctx, fmt.Sprintf("Looking up certificate collection by ID %d", state.ID.Value))
		resp, httpResp, err = collectionApi.NewGetCertificateCollectionsByIdRequest(ctx, int32(state.ID.Value)).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
	} else {
		tflog.Debug(ctx, fmt.Sprintf("Looking up certificate collection by name %q", state.Name.Value))
		resp, httpResp, err = collectionApi.NewGetCertificateCollectionsNameRequest(ctx, state.Name.Value).
			XKeyfactorRequestedWith("APIClient").
			XKeyfactorApiVersion("1").
			Execute()
	}

	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			response.Diagnostics.AddError(
				"Collection not found",
				fmt.Sprintf("Could not find certificate collection: %s", err.Error()),
			)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading certificate collection.",
			fmt.Sprintf("Could not read certificate collection: %s. Details: %s", err.Error(), body),
		)
		return
	}
	if resp == nil {
		response.Diagnostics.Append(nilAPIResponseDiagnostics(
			"Error reading certificate collection.",
			"reading certificate collection",
		)...)
		return
	}

	result := CertificateCollectionDataSourceState{}

	if resp.Id != nil {
		result.ID = types.Int64{Value: int64(*resp.Id)}
	} else {
		result.ID = types.Int64{Null: true}
	}

	if resp.Name.IsSet() && resp.Name.Get() != nil {
		result.Name = types.String{Value: *resp.Name.Get()}
	} else {
		result.Name = types.String{Null: true}
	}

	if resp.Description.IsSet() && resp.Description.Get() != nil {
		result.Description = types.String{Value: *resp.Description.Get()}
	} else {
		result.Description = types.String{Null: true}
	}

	if resp.Content.IsSet() && resp.Content.Get() != nil {
		result.Content = types.String{Value: *resp.Content.Get()}
	} else {
		result.Content = types.String{Null: true}
	}

	if resp.DuplicationField != nil {
		result.DuplicationField = types.Int64{Value: int64(*resp.DuplicationField)}
	} else {
		result.DuplicationField = types.Int64{Null: true}
	}

	if resp.ShowOnDashboard != nil {
		result.ShowOnDashboard = types.Bool{Value: *resp.ShowOnDashboard}
	} else {
		result.ShowOnDashboard = types.Bool{Null: true}
	}

	if resp.Favorite != nil {
		result.Favorite = types.Bool{Value: *resp.Favorite}
	} else {
		result.Favorite = types.Bool{Null: true}
	}

	if resp.EstimatedCertCount != nil {
		result.EstimatedCertCount = types.Int64{Value: int64(*resp.EstimatedCertCount)}
	} else {
		result.EstimatedCertCount = types.Int64{Null: true}
	}

	if resp.LastEstimated.IsSet() && resp.LastEstimated.Get() != nil {
		result.LastEstimated = types.String{Value: resp.LastEstimated.Get().String()}
	} else {
		result.LastEstimated = types.String{Null: true}
	}

	tflog.Debug(ctx, "Completed mapping certificate collection data")

	// When both id and name are declared, verify they resolve to the same
	// collection instead of silently letting id win. Without this check, a
	// stale/mistaken `name` in config that doesn't match the collection
	// actually resolved by `id` would be silently overwritten by the
	// server's real name with no diagnostic at all -- a silently-wrong-data
	// risk, not just a cosmetic mismatch, since callers may reasonably
	// assume the configured name was validated (PR #210 full-review finding
	// FIX-9).
	if idSet && nameSet {
		resolvedName := ""
		if !result.Name.Null {
			resolvedName = result.Name.Value
		}
		if resolvedName != state.Name.Value {
			response.Diagnostics.AddError(
				"Certificate collection id/name mismatch",
				fmt.Sprintf(
					"The certificate collection resolved by id %d has name %q, which does not match the configured "+
						"name %q. Remove one of `id`/`name`, or correct the mismatch.",
					state.ID.Value, resolvedName, state.Name.Value,
				),
			)
			return
		}
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	LogFunctionExit(ctx, "DataSourceCertificateCollection_Read")
}
