package keyfactor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceCertificateAuthorityType struct{}

func (d dataSourceCertificateAuthorityType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Description: "Reads a Keyfactor Command Certificate Authority by name or integer ID.",
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "Name (logical name) or integer ID of the certificate authority to look up.",
			},
			"id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Integer ID of the certificate authority.",
			},
			"logical_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Logical name of the certificate authority.",
			},
			"host_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Hostname or URL of the certificate authority server.",
			},
			"ca_type": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "CA type: 0 = Microsoft CA, 1 = third-party (e.g. EJBCA).",
			},
			"delegate": {
				Type:     types.BoolType,
				Computed: true,
			},
			"delegate_enrollment": {
				Type:     types.BoolType,
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
			"remote": {
				Type:     types.BoolType,
				Computed: true,
			},
			"agent": {
				Type:     types.StringType,
				Computed: true,
			},
			"standalone": {
				Type:     types.BoolType,
				Computed: true,
			},
			"use_ca_connector": {
				Type:     types.BoolType,
				Computed: true,
			},
			"connector_pool": {
				Type:     types.StringType,
				Computed: true,
			},
			"monitor_thresholds": {
				Type:     types.BoolType,
				Computed: true,
			},
			"issuance_max": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"issuance_min": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"failure_max": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"rfc_enforcement": {
				Type:     types.BoolType,
				Computed: true,
			},
			"properties": {
				Type:     types.StringType,
				Computed: true,
			},
			"allowed_enrollment_types": {
				Type:     types.Int64Type,
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
			"enforce_unique_dn": {
				Type:     types.BoolType,
				Computed: true,
			},
			"subscriber_terms": {
				Type:     types.BoolType,
				Computed: true,
			},
			"allow_one_click_renewals": {
				Type:     types.BoolType,
				Computed: true,
			},
			"new_end_entity_on_renew_and_reissue": {
				Type:     types.BoolType,
				Computed: true,
			},
			"use_allowed_requesters": {
				Type:     types.BoolType,
				Computed: true,
			},
			"allowed_requesters": {
				Type:     types.ListType{ElemType: types.StringType},
				Computed: true,
			},
			"explicit_credentials": {
				Type:     types.BoolType,
				Computed: true,
			},
			"explicit_user": {
				Type:     types.StringType,
				Computed: true,
			},
			"auth_certificate_issued_dn": {
				Type:     types.StringType,
				Computed: true,
			},
			"auth_certificate_issuer_dn": {
				Type:     types.StringType,
				Computed: true,
			},
			"auth_certificate_thumbprint": {
				Type:     types.StringType,
				Computed: true,
			},
			"token_url": {
				Type:     types.StringType,
				Computed: true,
			},
			"client_id": {
				Type:     types.StringType,
				Computed: true,
			},
			"scope": {
				Type:     types.StringType,
				Computed: true,
			},
			"audience": {
				Type:     types.StringType,
				Computed: true,
			},
			"full_scan_interval_minutes": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"incremental_scan_interval_minutes": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"threshold_check_interval_minutes": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"agent_name": {
				Type:     types.StringType,
				Computed: true,
			},
			"agent_username": {
				Type:     types.StringType,
				Computed: true,
			},
			"denial_max": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"last_scan": {
				Type:     types.StringType,
				Computed: true,
			},
		},
	}, nil
}

func (d dataSourceCertificateAuthorityType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertificateAuthority{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceCertificateAuthority struct {
	p provider
}

// KeyfactorCertificateAuthorityDataSource is the Terraform state model for the data source.
type KeyfactorCertificateAuthorityDataSource struct {
	Identifier types.String `tfsdk:"identifier"`

	// All fields from the resource except write-only secrets
	ID          types.String `tfsdk:"id"`
	LogicalName types.String `tfsdk:"logical_name"`
	HostName    types.String `tfsdk:"host_name"`
	CAType      types.Int64  `tfsdk:"ca_type"`

	Delegate            types.Bool   `tfsdk:"delegate"`
	DelegateEnrollment  types.Bool   `tfsdk:"delegate_enrollment"`
	ForestRoot          types.String `tfsdk:"forest_root"`
	ConfigurationTenant types.String `tfsdk:"configuration_tenant"`
	Remote              types.Bool   `tfsdk:"remote"`
	Agent               types.String `tfsdk:"agent"`
	Standalone          types.Bool   `tfsdk:"standalone"`
	UseCAConnector      types.Bool   `tfsdk:"use_ca_connector"`
	ConnectorPool       types.String `tfsdk:"connector_pool"`

	MonitorThresholds types.Bool  `tfsdk:"monitor_thresholds"`
	IssuanceMax       types.Int64 `tfsdk:"issuance_max"`
	IssuanceMin       types.Int64 `tfsdk:"issuance_min"`
	FailureMax        types.Int64 `tfsdk:"failure_max"`

	RFCEnforcement                types.Bool   `tfsdk:"rfc_enforcement"`
	Properties                    types.String `tfsdk:"properties"`
	AllowedEnrollmentTypes        types.Int64  `tfsdk:"allowed_enrollment_types"`
	KeyRetention                  types.Int64  `tfsdk:"key_retention"`
	KeyRetentionDays              types.Int64  `tfsdk:"key_retention_days"`
	EnforceUniqueDN               types.Bool   `tfsdk:"enforce_unique_dn"`
	SubscriberTerms               types.Bool   `tfsdk:"subscriber_terms"`
	AllowOneClickRenewals         types.Bool   `tfsdk:"allow_one_click_renewals"`
	NewEndEntityOnRenewAndReissue types.Bool   `tfsdk:"new_end_entity_on_renew_and_reissue"`

	UseAllowedRequesters types.Bool `tfsdk:"use_allowed_requesters"`
	AllowedRequesters    types.List `tfsdk:"allowed_requesters"`

	ExplicitCredentials types.Bool   `tfsdk:"explicit_credentials"`
	ExplicitUser        types.String `tfsdk:"explicit_user"`

	AuthCertificateIssuedDN   types.String `tfsdk:"auth_certificate_issued_dn"`
	AuthCertificateIssuerDN   types.String `tfsdk:"auth_certificate_issuer_dn"`
	AuthCertificateThumbprint types.String `tfsdk:"auth_certificate_thumbprint"`

	TokenURL types.String `tfsdk:"token_url"`
	ClientID types.String `tfsdk:"client_id"`
	Scope    types.String `tfsdk:"scope"`
	Audience types.String `tfsdk:"audience"`

	FullScanIntervalMinutes        types.Int64 `tfsdk:"full_scan_interval_minutes"`
	IncrementalScanIntervalMinutes types.Int64 `tfsdk:"incremental_scan_interval_minutes"`
	ThresholdCheckIntervalMinutes  types.Int64 `tfsdk:"threshold_check_interval_minutes"`

	AgentName     types.String `tfsdk:"agent_name"`
	AgentUsername types.String `tfsdk:"agent_username"`
	DenialMax     types.Int64  `tfsdk:"denial_max"`
	LastScan      types.String `tfsdk:"last_scan"`
}

func (d dataSourceCertificateAuthority) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	LogFunctionEntry(ctx, "dataSourceCertificateAuthority.Read")

	var config KeyfactorCertificateAuthorityDataSource
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	identifier := config.Identifier.Value
	tflog.Info(ctx, fmt.Sprintf("Reading certificate authority with identifier %q", identifier))

	caAPI := d.p.sdkClient.V1.CertificateAuthorityApi

	// Try as integer ID first
	if id, err := strconv.Atoi(identifier); err == nil {
		req := caAPI.NewGetCertificateAuthorityByIdRequest(ctx, int32(id))
		resp, httpResp, err := req.Execute()
		if err != nil {
			body := readHTTPResponseBody(httpResp)
			response.Diagnostics.AddError(
				"Error reading certificate authority.",
				fmt.Sprintf("Could not read certificate authority %d: %s. Details: %s", id, err.Error(), body),
			)
			return
		}
		state := caResponseToDataSourceState(resp, config.Identifier)
		diags = response.State.Set(ctx, &state)
		response.Diagnostics.Append(diags...)
		return
	}

	// Search by logical name
	req := caAPI.NewGetCertificateAuthorityRequest(ctx)
	allCAs, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error listing certificate authorities.",
			fmt.Sprintf("Could not list certificate authorities: %s. Details: %s", err.Error(), body),
		)
		return
	}

	for _, ca := range allCAs {
		if strings.EqualFold(ca.GetLogicalName(), identifier) {
			state := caResponseToDataSourceState(&ca, config.Identifier)
			diags = response.State.Set(ctx, &state)
			response.Diagnostics.Append(diags...)
			LogFunctionExit(ctx, "dataSourceCertificateAuthority.Read")
			return
		}
	}

	response.Diagnostics.AddError(
		"Certificate authority not found.",
		fmt.Sprintf("No certificate authority with name %q was found.", identifier),
	)
}

func caResponseToDataSourceState(resp *v1.CertificateAuthoritiesCertificateAuthorityResponse, identifier types.String) KeyfactorCertificateAuthorityDataSource {
	rs := caResponseToState(resp)

	return KeyfactorCertificateAuthorityDataSource{
		Identifier:  identifier,
		ID:          rs.ID,
		LogicalName: rs.LogicalName,
		HostName:    rs.HostName,
		CAType:      rs.CAType,

		Delegate:            rs.Delegate,
		DelegateEnrollment:  rs.DelegateEnrollment,
		ForestRoot:          rs.ForestRoot,
		ConfigurationTenant: rs.ConfigurationTenant,
		Remote:              rs.Remote,
		Agent:               rs.Agent,
		Standalone:          rs.Standalone,
		UseCAConnector:      rs.UseCAConnector,
		ConnectorPool:       rs.ConnectorPool,

		MonitorThresholds: rs.MonitorThresholds,
		IssuanceMax:       rs.IssuanceMax,
		IssuanceMin:       rs.IssuanceMin,
		FailureMax:        rs.FailureMax,

		RFCEnforcement:                rs.RFCEnforcement,
		Properties:                    rs.Properties,
		AllowedEnrollmentTypes:        rs.AllowedEnrollmentTypes,
		KeyRetention:                  rs.KeyRetention,
		KeyRetentionDays:              rs.KeyRetentionDays,
		EnforceUniqueDN:               rs.EnforceUniqueDN,
		SubscriberTerms:               rs.SubscriberTerms,
		AllowOneClickRenewals:         rs.AllowOneClickRenewals,
		NewEndEntityOnRenewAndReissue: rs.NewEndEntityOnRenewAndReissue,

		UseAllowedRequesters: rs.UseAllowedRequesters,
		AllowedRequesters:    rs.AllowedRequesters,

		ExplicitCredentials: rs.ExplicitCredentials,
		ExplicitUser:        rs.ExplicitUser,

		AuthCertificateIssuedDN:   rs.AuthCertificateIssuedDN,
		AuthCertificateIssuerDN:   rs.AuthCertificateIssuerDN,
		AuthCertificateThumbprint: rs.AuthCertificateThumbprint,

		TokenURL: rs.TokenURL,
		ClientID: rs.ClientID,
		Scope:    rs.Scope,
		Audience: rs.Audience,

		FullScanIntervalMinutes:        rs.FullScanIntervalMinutes,
		IncrementalScanIntervalMinutes: rs.IncrementalScanIntervalMinutes,
		ThresholdCheckIntervalMinutes:  rs.ThresholdCheckIntervalMinutes,

		AgentName:     rs.AgentName,
		AgentUsername: rs.AgentUsername,
		DenialMax:     rs.DenialMax,
		LastScan:      rs.LastScan,
	}
}
