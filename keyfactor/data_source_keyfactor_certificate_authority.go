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
				Description: "Integer ID of the certificate authority assigned by Keyfactor Command.",
			},
			"logical_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the logical name of the certificate authority.",
			},
			"host_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the DNS hostname or URL of the certificate authority.",
			},
			"ca_type": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the type of CA: 0 = DCOM (Microsoft ADCS) or 1 = HTTPS (e.g. EJBCA).",
			},
			"delegate": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether management interactions should be done in the context of the requesting user.",
			},
			"delegate_enrollment": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether enrollment should be done in the context of the requesting user.",
			},
			"forest_root": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the forest root name or DNS domain name (retained for legacy purposes).",
			},
			"configuration_tenant": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the forest root name or DNS domain name for the certificate authority.",
			},
			"remote": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether communications are done via a Keyfactor Universal Orchestrator.",
			},
			"agent": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the GUID of the Keyfactor Universal Orchestrator configured to manage the certificate authority.",
			},
			"standalone": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether the certificate authority is a standalone CA.",
			},
			"use_ca_connector": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether communications are done via a CA Connector Client.",
			},
			"connector_pool": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the name of the connector pool to use with the CA Connector Client.",
			},
			"monitor_thresholds": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether threshold monitoring is enabled with email alerts.",
			},
			"issuance_max": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer that sets the maximum number of certificates that can be issued before an alert is triggered.",
			},
			"issuance_min": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer that sets the minimum number of certificates that should be issued before an alert is triggered.",
			},
			"failure_max": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer that sets the maximum number of certificate requests that can fail before an alert is triggered.",
			},
			"rfc_enforcement": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether enrollments must include at least one DNS SAN.",
			},
			"properties": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating additional properties, storing configuration for the Sync External Certificates option.",
			},
			"allowed_enrollment_types": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer that sets the type(s) of enrollment that are allowed through Keyfactor Command for the certificate authority: 0=none, 1=PFX, 2=CSR, 3=both.",
			},
			"key_retention": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer that sets the type of key retention to enable for the certificate authority: 0=None, 1=SettingDriven, 2=Always, 3=Never.",
			},
			"key_retention_days": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "An integer indicating the number of days for which to retain private keys before deletion.",
			},
			"enforce_unique_dn": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether the unique DN requirement is enforced on the CA.",
			},
			"subscriber_terms": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether to add a checkbox forcing users to agree to terms.",
			},
			"allow_one_click_renewals": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether the CA will allow One-Click Renewal on certificates.",
			},
			"new_end_entity_on_renew_and_reissue": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean setting whether renewal requests create new end entities.",
			},
			"use_for_enrollment": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether this CA is available for certificate enrollment.",
			},
			"certificate_cleanup_enabled": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether certificate cleanup is enabled for this CA.",
			},
			"delete_with_archived_key": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether to delete the certificate when its archived key is deleted.",
			},
			"time_after_expiration": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Time value after expiration before cleanup occurs. Used with time_after_expiration_units.",
			},
			"time_after_expiration_units": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Units for time_after_expiration: 0=Days, 1=Weeks, 2=Months.",
			},
			"use_allowed_requesters": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether the allowed requesters option is enabled. Applies to standalone CAs only.",
			},
			"allowed_requesters": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "An array of strings indicating Keyfactor Command security roles that are allowed to enroll for certificates via Keyfactor Command for this CA. Applies to standalone CAs only.",
			},
			"explicit_credentials": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "A Boolean that sets whether explicit credentials are enabled for this certificate authority.",
			},
			"explicit_user": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the username in DOMAIN\\username format for service account credentials.",
			},
			"auth_certificate_issued_dn": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Issued DN of the authentication certificate.",
			},
			"auth_certificate_issuer_dn": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Issuer DN of the authentication certificate.",
			},
			"auth_certificate_thumbprint": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Thumbprint of the authentication certificate.",
			},
			"token_url": {
				Type:        types.StringType,
				Computed:    true,
				Description: "For HTTPS CAs, a string indicating the bearer token URL of the identity provider.",
			},
			"client_id": {
				Type:        types.StringType,
				Computed:    true,
				Description: "For HTTPS CAs, a string specifying the client ID used to authenticate when OAuth authentication is selected.",
			},
			"scope": {
				Type:        types.StringType,
				Computed:    true,
				Description: "For HTTPS CAs, a string indicating scopes included in token requests, separated by spaces.",
			},
			"audience": {
				Type:        types.StringType,
				Computed:    true,
				Description: "For HTTPS CAs, a string specifying the audience to include in token requests to the identity provider.",
			},
			"full_scan_interval_minutes": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Interval in minutes for the full synchronization schedule of this certificate authority. One of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720.",
			},
			"incremental_scan_interval_minutes": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Interval in minutes for the incremental synchronization schedule of this certificate authority. One of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720.",
			},
			"threshold_check_interval_minutes": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Interval in minutes for the threshold monitoring check schedule on this CA. One of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720.",
			},
			"agent_name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Name of the orchestrator agent managing this CA.",
			},
			"agent_username": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Username of the orchestrator agent managing this CA.",
			},
			"denial_max": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Maximum denial count.",
			},
			"last_scan": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string indicating the date in UTC on which a synchronization was last performed.",
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

	UseForEnrollment          types.Bool  `tfsdk:"use_for_enrollment"`
	CertificateCleanupEnabled types.Bool  `tfsdk:"certificate_cleanup_enabled"`
	DeleteWithArchivedKey     types.Bool  `tfsdk:"delete_with_archived_key"`
	TimeAfterExpiration       types.Int64 `tfsdk:"time_after_expiration"`
	TimeAfterExpirationUnits  types.Int64 `tfsdk:"time_after_expiration_units"`

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

		UseForEnrollment:          rs.UseForEnrollment,
		CertificateCleanupEnabled: rs.CertificateCleanupEnabled,
		DeleteWithArchivedKey:     rs.DeleteWithArchivedKey,
		TimeAfterExpiration:       rs.TimeAfterExpiration,
		TimeAfterExpirationUnits:  rs.TimeAfterExpirationUnits,

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
