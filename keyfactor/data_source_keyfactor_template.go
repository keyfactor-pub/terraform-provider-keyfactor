package keyfactor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceCertificateTemplateType struct{}

func (d dataSourceCertificateTemplateType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	// Build from the resource schema, adding identifier and making all fields Computed.
	return tfsdk.Schema{
		Description: "Reads a Keyfactor Command Certificate Template by name (common name or display name) or integer ID.",
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Common name, display name, or integer ID of the template to look up.",
			},
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Integer ID of the certificate template.",
			},
			"common_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Short name (common name) of the template.",
			},
			"template_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Display name of the template.",
			},
			"display_name": {
				Type:     types.StringType,
				Computed: true,
			},
			"oid": {
				Type:     types.StringType,
				Computed: true,
			},
			"key_size": {
				Type:     types.StringType,
				Computed: true,
			},
			"key_type": {
				Type:     types.StringType,
				Computed: true,
			},
			"key_types": {
				Type:     types.StringType,
				Computed: true,
			},
			"forest_root": {
				Type:     types.StringType,
				Computed: true,
			},
			"configuration_tenant": {
				Type:     types.StringType,
				Computed: true,
			},
			"key_archival": {
				Type:     types.BoolType,
				Computed: true,
			},
			"friendly_name": {
				Type:     types.StringType,
				Computed: true,
			},
			"key_retention": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"key_retention_days": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"allowed_enrollment_types": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Bitmask: 0=none, 1=PFX, 2=CSR, 3=both.",
			},
			"use_allowed_requesters": {
				Type:     types.BoolType,
				Computed: true,
			},
			"allowed_requesters": {
				Type:     types.ListType{ElemType: types.StringType},
				Computed: true,
			},
			"requires_approval": {
				Type:     types.BoolType,
				Computed: true,
			},
			"allow_one_click_renewals": {
				Type:     types.BoolType,
				Computed: true,
			},
			"key_usage": {
				Type:     types.Int64Type,
				Computed: true,
			},

			"template_policy": {
				Computed:   true,
				Attributes: tfsdk.SingleNestedAttributes(templatePolicySchema()),
			},

			"template_regexes": {
				Computed: true,
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"subject_part":   {Type: types.StringType, Computed: true},
					"regex":          {Type: types.StringType, Computed: true},
					"error":          {Type: types.StringType, Computed: true},
					"case_sensitive": {Type: types.BoolType, Computed: true},
				}),
			},
			"template_defaults": {
				Computed: true,
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"subject_part": {Type: types.StringType, Computed: true},
					"value":        {Type: types.StringType, Computed: true},
				}),
			},
			"enrollment_fields": {
				Computed: true,
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"id":        {Type: types.Int64Type, Computed: true},
					"name":      {Type: types.StringType, Computed: true},
					"data_type": {Type: types.Int64Type, Computed: true},
					"options":   {Type: types.ListType{ElemType: types.StringType}, Computed: true},
				}),
			},
			"metadata_fields": {
				Computed: true,
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"id":             {Type: types.Int64Type, Computed: true},
					"metadata_id":    {Type: types.Int64Type, Computed: true},
					"default_value":  {Type: types.StringType, Computed: true},
					"validation":     {Type: types.StringType, Computed: true},
					"enrollment":     {Type: types.Int64Type, Computed: true},
					"message":        {Type: types.StringType, Computed: true},
					"case_sensitive": {Type: types.BoolType, Computed: true},
				}),
			},
			"extended_key_usages": {
				Computed: true,
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"id":           {Type: types.Int64Type, Computed: true},
					"oid":          {Type: types.StringType, Computed: true},
					"display_name": {Type: types.StringType, Computed: true},
				}),
			},
			"key_algorithms": {
				Computed: true,
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"algorithm":   {Type: types.StringType, Computed: true},
					"bit_lengths": {Type: types.ListType{ElemType: types.Int64Type}, Computed: true},
					"curves":      {Type: types.ListType{ElemType: types.StringType}, Computed: true},
				}),
			},

			"manageability":               {Type: types.Int64Type, Computed: true},
			"certificate_cleanup_enabled": {Type: types.BoolType, Computed: true},
			"time_after_expiration":       {Type: types.Int64Type, Computed: true},
			"time_after_expiration_units": {Type: types.Int64Type, Computed: true},
			"delete_with_archived_key":    {Type: types.BoolType, Computed: true},
		},
	}, nil
}

func (d dataSourceCertificateTemplateType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertificateTemplate{p: *(p.(*provider))}, nil
}

type dataSourceCertificateTemplate struct {
	p provider
}

type KeyfactorCertificateTemplateDataSource struct {
	Identifier types.String `tfsdk:"identifier"`

	// Same fields as resource state
	ID                     types.Int64  `tfsdk:"id"`
	CommonName             types.String `tfsdk:"common_name"`
	TemplateName           types.String `tfsdk:"template_name"`
	DisplayName            types.String `tfsdk:"display_name"`
	OID                    types.String `tfsdk:"oid"`
	KeySize                types.String `tfsdk:"key_size"`
	KeyType                types.String `tfsdk:"key_type"`
	KeyTypes               types.String `tfsdk:"key_types"`
	ForestRoot             types.String `tfsdk:"forest_root"`
	ConfigurationTenant    types.String `tfsdk:"configuration_tenant"`
	KeyArchival            types.Bool   `tfsdk:"key_archival"`
	FriendlyName           types.String `tfsdk:"friendly_name"`
	KeyRetention           types.Int64  `tfsdk:"key_retention"`
	KeyRetentionDays       types.Int64  `tfsdk:"key_retention_days"`
	AllowedEnrollmentTypes types.Int64  `tfsdk:"allowed_enrollment_types"`
	UseAllowedRequesters   types.Bool   `tfsdk:"use_allowed_requesters"`
	AllowedRequesters      types.List   `tfsdk:"allowed_requesters"`
	RequiresApproval       types.Bool   `tfsdk:"requires_approval"`
	AllowOneClickRenewals  types.Bool   `tfsdk:"allow_one_click_renewals"`
	KeyUsage               types.Int64  `tfsdk:"key_usage"`

	TemplatePolicy    *TemplatePolicyState           `tfsdk:"template_policy"`
	TemplateRegexes   []TemplateRegexEntry           `tfsdk:"template_regexes"`
	TemplateDefaults  []TemplateDefaultEntry         `tfsdk:"template_defaults"`
	EnrollmentFields  []TemplateEnrollmentFieldEntry `tfsdk:"enrollment_fields"`
	MetadataFields    []TemplateMetadataFieldEntry   `tfsdk:"metadata_fields"`
	ExtendedKeyUsages []TemplateEKUEntry             `tfsdk:"extended_key_usages"`
	KeyAlgorithms     []TemplateKeyAlgorithmEntry    `tfsdk:"key_algorithms"`

	Manageability             types.Int64 `tfsdk:"manageability"`
	CertificateCleanupEnabled types.Bool  `tfsdk:"certificate_cleanup_enabled"`
	TimeAfterExpiration       types.Int64 `tfsdk:"time_after_expiration"`
	TimeAfterExpirationUnits  types.Int64 `tfsdk:"time_after_expiration_units"`
	DeleteWithArchivedKey     types.Bool  `tfsdk:"delete_with_archived_key"`
}

func (d dataSourceCertificateTemplate) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	LogFunctionEntry(ctx, "dataSourceCertificateTemplate.Read")

	var config KeyfactorCertificateTemplateDataSource
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	identifier := config.Identifier.Value
	tflog.Info(ctx, fmt.Sprintf("Reading certificate template with identifier %q", identifier))

	templateAPI := d.p.sdkClient.V1.TemplateApi

	// Try as integer ID first
	if id, err := strconv.Atoi(identifier); err == nil {
		req := templateAPI.NewGetTemplatesByIdRequest(ctx, int32(id))
		resp, httpResp, err := req.Execute()
		if err != nil {
			body := readHTTPResponseBody(httpResp)
			response.Diagnostics.AddError(
				"Error reading certificate template.",
				fmt.Sprintf("Could not read template %d: %s. Details: %s", id, err.Error(), body),
			)
			return
		}
		rs := templateResponseToState(resp)
		state := templateResourceToDataSource(rs, config.Identifier)
		diags = response.State.Set(ctx, &state)
		response.Diagnostics.Append(diags...)
		LogFunctionExit(ctx, "dataSourceCertificateTemplate.Read")
		return
	}

	// Search by name (CommonName or TemplateName match)
	listReq := templateAPI.NewGetTemplatesRequest(ctx)
	allTemplates, httpResp, err := listReq.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error listing certificate templates.",
			fmt.Sprintf("Could not list templates: %s. Details: %s", err.Error(), body),
		)
		return
	}

	for _, t := range allTemplates {
		if strings.EqualFold(t.GetCommonName(), identifier) ||
			strings.EqualFold(t.GetTemplateName(), identifier) ||
			strings.EqualFold(t.GetDisplayName(), identifier) {

			// Fetch full details by ID
			detailReq := templateAPI.NewGetTemplatesByIdRequest(ctx, t.GetId())
			resp, httpResp, err := detailReq.Execute()
			if err != nil {
				body := readHTTPResponseBody(httpResp)
				response.Diagnostics.AddError(
					"Error reading certificate template.",
					fmt.Sprintf("Could not read template %d: %s. Details: %s", t.GetId(), err.Error(), body),
				)
				return
			}
			rs := templateResponseToState(resp)
			state := templateResourceToDataSource(rs, config.Identifier)
			diags = response.State.Set(ctx, &state)
			response.Diagnostics.Append(diags...)
			LogFunctionExit(ctx, "dataSourceCertificateTemplate.Read")
			return
		}
	}

	response.Diagnostics.AddError(
		"Certificate template not found.",
		fmt.Sprintf("No template with identifier %q was found.", identifier),
	)
}

func templateResourceToDataSource(rs KeyfactorCertificateTemplateState, identifier types.String) KeyfactorCertificateTemplateDataSource {
	return KeyfactorCertificateTemplateDataSource{
		Identifier:             identifier,
		ID:                     rs.ID,
		CommonName:             rs.CommonName,
		TemplateName:           rs.TemplateName,
		DisplayName:            rs.DisplayName,
		OID:                    rs.OID,
		KeySize:                rs.KeySize,
		KeyType:                rs.KeyType,
		KeyTypes:               rs.KeyTypes,
		ForestRoot:             rs.ForestRoot,
		ConfigurationTenant:    rs.ConfigurationTenant,
		KeyArchival:            rs.KeyArchival,
		FriendlyName:           rs.FriendlyName,
		KeyRetention:           rs.KeyRetention,
		KeyRetentionDays:       rs.KeyRetentionDays,
		AllowedEnrollmentTypes: rs.AllowedEnrollmentTypes,
		UseAllowedRequesters:   rs.UseAllowedRequesters,
		AllowedRequesters:      rs.AllowedRequesters,
		RequiresApproval:       rs.RequiresApproval,
		AllowOneClickRenewals:  rs.AllowOneClickRenewals,
		KeyUsage:               rs.KeyUsage,

		TemplatePolicy:    rs.TemplatePolicy,
		TemplateRegexes:   rs.TemplateRegexes,
		TemplateDefaults:  rs.TemplateDefaults,
		EnrollmentFields:  rs.EnrollmentFields,
		MetadataFields:    rs.MetadataFields,
		ExtendedKeyUsages: rs.ExtendedKeyUsages,
		KeyAlgorithms:     rs.KeyAlgorithms,

		Manageability:             rs.Manageability,
		CertificateCleanupEnabled: rs.CertificateCleanupEnabled,
		TimeAfterExpiration:       rs.TimeAfterExpiration,
		TimeAfterExpirationUnits:  rs.TimeAfterExpirationUnits,
		DeleteWithArchivedKey:     rs.DeleteWithArchivedKey,
	}
}
