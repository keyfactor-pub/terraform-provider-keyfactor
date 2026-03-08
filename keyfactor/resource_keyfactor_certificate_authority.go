package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceCertificateAuthorityType struct{}

func (r resourceCertificateAuthorityType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Description: "Manages a Keyfactor Command Certificate Authority (CA). Secret fields (explicit_password, auth_certificate, auth_certificate_password, client_secret) are write-only — the server never returns plaintext values, so provider reads preserve configured values from state.",
		Attributes: map[string]tfsdk.Attribute{
			// --- Identity ---
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Integer ID of the certificate authority.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"logical_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Logical name for the certificate authority.",
			},
			"host_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Hostname or URL of the certificate authority server.",
			},
			"ca_type": {
				Type:          types.Int64Type,
				Required:      true,
				Description:   "CA type: 0 = Microsoft CA, 1 = third-party (e.g. EJBCA). Changing this forces a new resource.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},

			// --- Delegation & Connectivity ---
			"delegate": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether the CA is delegated.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"delegate_enrollment": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether enrollment is delegated for this CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"forest_root": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Forest root for the CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"configuration_tenant": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Configuration tenant for the CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"remote": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether the CA is remote.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"agent": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Agent identifier (GUID) for this CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"standalone": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether the CA is standalone.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"use_ca_connector": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to use the CA connector.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"connector_pool": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Connector pool name.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Monitoring & Thresholds ---
			"monitor_thresholds": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to monitor thresholds for this CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"issuance_max": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Maximum issuance threshold.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"issuance_min": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Minimum issuance threshold.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"failure_max": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Maximum failure threshold.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Enrollment & Policy ---
			"rfc_enforcement": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to enforce RFC compliance.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"properties": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "JSON string of CA properties.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allowed_enrollment_types": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Bitmask of allowed enrollment types (0=none, 1=PFX, 2=CSR, 3=both).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_retention": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Key retention policy: 0=None, 1=SettingDriven, 2=Always, 3=Never.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_retention_days": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Number of days to retain keys.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"enforce_unique_dn": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to enforce unique distinguished names.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"subscriber_terms": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether subscriber terms are enabled.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allow_one_click_renewals": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether one-click renewals are allowed.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"new_end_entity_on_renew_and_reissue": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to create a new end entity on renew and reissue (EJBCA).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Requesters ---
			"use_allowed_requesters": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether to restrict enrollment to specific requesters.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allowed_requesters": {
				Type:        types.ListType{ElemType: types.StringType},
				Optional:    true,
				Description: "List of allowed requester identities.",
			},

			// --- Explicit Credentials (write-only secrets) ---
			"explicit_credentials": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "Whether explicit credentials are configured for this CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"explicit_user": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Username for explicit credentials.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"explicit_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Password for explicit credentials. Write-only; cannot be read back from the server.",
			},

			// --- Auth Certificate (write-only) ---
			"auth_certificate": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64-encoded PFX data for the authentication certificate. Write-only.",
			},
			"auth_certificate_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Password for the authentication certificate PFX. Write-only.",
			},

			// --- Auth Certificate metadata (read-only from server) ---
			"auth_certificate_issued_dn": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Issued DN of the authentication certificate (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"auth_certificate_issuer_dn": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Issuer DN of the authentication certificate (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"auth_certificate_thumbprint": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Thumbprint of the authentication certificate (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- OAuth Config ---
			"token_url": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "OAuth token URL for third-party CA authentication.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"client_id": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "OAuth client ID.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"client_secret": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "OAuth client secret. Write-only; cannot be read back from the server.",
			},
			"scope": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "OAuth scope.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"audience": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "OAuth audience.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Schedules (flat interval minutes) ---
			"full_scan_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for full CA scans.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"incremental_scan_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for incremental CA scans.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"threshold_check_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for threshold checks.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Read-only ---
			"agent_name": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Name of the agent (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"agent_username": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Username of the agent (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"denial_max": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "Maximum denial count (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"last_scan": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Timestamp of the last scan (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
		},
	}, nil
}

func (r resourceCertificateAuthorityType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceCertificateAuthority{
		p: *(p.(*provider)),
	}, nil
}

type resourceCertificateAuthority struct {
	p provider
}

// KeyfactorCertificateAuthority is the Terraform state model.
type KeyfactorCertificateAuthority struct {
	// Identity
	ID          types.String `tfsdk:"id"`
	LogicalName types.String `tfsdk:"logical_name"`
	HostName    types.String `tfsdk:"host_name"`
	CAType      types.Int64  `tfsdk:"ca_type"`

	// Delegation & Connectivity
	Delegate            types.Bool   `tfsdk:"delegate"`
	DelegateEnrollment  types.Bool   `tfsdk:"delegate_enrollment"`
	ForestRoot          types.String `tfsdk:"forest_root"`
	ConfigurationTenant types.String `tfsdk:"configuration_tenant"`
	Remote              types.Bool   `tfsdk:"remote"`
	Agent               types.String `tfsdk:"agent"`
	Standalone          types.Bool   `tfsdk:"standalone"`
	UseCAConnector      types.Bool   `tfsdk:"use_ca_connector"`
	ConnectorPool       types.String `tfsdk:"connector_pool"`

	// Monitoring
	MonitorThresholds types.Bool  `tfsdk:"monitor_thresholds"`
	IssuanceMax       types.Int64 `tfsdk:"issuance_max"`
	IssuanceMin       types.Int64 `tfsdk:"issuance_min"`
	FailureMax        types.Int64 `tfsdk:"failure_max"`

	// Enrollment & Policy
	RFCEnforcement                types.Bool   `tfsdk:"rfc_enforcement"`
	Properties                    types.String `tfsdk:"properties"`
	AllowedEnrollmentTypes        types.Int64  `tfsdk:"allowed_enrollment_types"`
	KeyRetention                  types.Int64  `tfsdk:"key_retention"`
	KeyRetentionDays              types.Int64  `tfsdk:"key_retention_days"`
	EnforceUniqueDN               types.Bool   `tfsdk:"enforce_unique_dn"`
	SubscriberTerms               types.Bool   `tfsdk:"subscriber_terms"`
	AllowOneClickRenewals         types.Bool   `tfsdk:"allow_one_click_renewals"`
	NewEndEntityOnRenewAndReissue types.Bool   `tfsdk:"new_end_entity_on_renew_and_reissue"`

	// Requesters
	UseAllowedRequesters types.Bool `tfsdk:"use_allowed_requesters"`
	AllowedRequesters    types.List `tfsdk:"allowed_requesters"`

	// Explicit Credentials
	ExplicitCredentials types.Bool   `tfsdk:"explicit_credentials"`
	ExplicitUser        types.String `tfsdk:"explicit_user"`
	ExplicitPassword    types.String `tfsdk:"explicit_password"`

	// Auth Certificate
	AuthCertificate         types.String `tfsdk:"auth_certificate"`
	AuthCertificatePassword types.String `tfsdk:"auth_certificate_password"`

	// Auth Certificate metadata (read-only)
	AuthCertificateIssuedDN   types.String `tfsdk:"auth_certificate_issued_dn"`
	AuthCertificateIssuerDN   types.String `tfsdk:"auth_certificate_issuer_dn"`
	AuthCertificateThumbprint types.String `tfsdk:"auth_certificate_thumbprint"`

	// OAuth
	TokenURL     types.String `tfsdk:"token_url"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	Scope        types.String `tfsdk:"scope"`
	Audience     types.String `tfsdk:"audience"`

	// Schedules
	FullScanIntervalMinutes        types.Int64 `tfsdk:"full_scan_interval_minutes"`
	IncrementalScanIntervalMinutes types.Int64 `tfsdk:"incremental_scan_interval_minutes"`
	ThresholdCheckIntervalMinutes  types.Int64 `tfsdk:"threshold_check_interval_minutes"`

	// Read-only
	AgentName     types.String `tfsdk:"agent_name"`
	AgentUsername types.String `tfsdk:"agent_username"`
	DenialMax     types.Int64  `tfsdk:"denial_max"`
	LastScan      types.String `tfsdk:"last_scan"`
}

// caResponseToState converts a server response into the Terraform state model.
// Secret fields (explicit_password, auth_certificate, auth_certificate_password, client_secret)
// must be set separately from plan/state because the server never returns plaintext.
func caResponseToState(resp *v1.CertificateAuthoritiesCertificateAuthorityResponse) KeyfactorCertificateAuthority {
	state := KeyfactorCertificateAuthority{
		ID:          types.String{Value: strconv.Itoa(int(resp.GetId()))},
		LogicalName: types.String{Value: resp.GetLogicalName()},
		HostName:    types.String{Value: resp.GetHostName()},
		CAType:      types.Int64{Value: int64(resp.GetCAType())},

		Delegate:            types.Bool{Value: resp.GetDelegate()},
		DelegateEnrollment:  types.Bool{Value: resp.GetDelegateEnrollment()},
		ForestRoot:          types.String{Value: resp.GetForestRoot()},
		ConfigurationTenant: types.String{Value: resp.GetConfigurationTenant()},
		Remote:              types.Bool{Value: resp.GetRemote()},
		Standalone:          types.Bool{Value: resp.GetStandalone()},
		UseCAConnector:      types.Bool{Value: resp.GetUseCAConnector()},
		ConnectorPool:       types.String{Value: resp.GetConnectorPool()},

		MonitorThresholds: types.Bool{Value: resp.GetMonitorThresholds()},
		IssuanceMax:       nullableInt32ToTfInt64(resp.IssuanceMax),
		IssuanceMin:       nullableInt32ToTfInt64(resp.IssuanceMin),
		FailureMax:        nullableInt32ToTfInt64(resp.FailureMax),

		RFCEnforcement:                types.Bool{Value: resp.GetRFCEnforcement()},
		Properties:                    types.String{Value: resp.GetProperties()},
		AllowedEnrollmentTypes:        types.Int64{Value: int64(resp.GetAllowedEnrollmentTypes())},
		KeyRetention:                  types.Int64{Value: int64(resp.GetKeyRetention())},
		KeyRetentionDays:              nullableInt32ToTfInt64(resp.KeyRetentionDays),
		EnforceUniqueDN:               types.Bool{Value: resp.GetEnforceUniqueDN()},
		SubscriberTerms:               types.Bool{Value: resp.GetSubscriberTerms()},
		AllowOneClickRenewals:         types.Bool{Value: resp.GetAllowOneClickRenewals()},
		NewEndEntityOnRenewAndReissue: types.Bool{Value: resp.GetNewEndEntityOnRenewAndReissue()},

		UseAllowedRequesters: types.Bool{Value: resp.GetUseAllowedRequesters()},

		ExplicitCredentials: types.Bool{Value: resp.GetExplicitCredentials()},
		ExplicitUser:        nullableStringToTfString(resp.ExplicitUser),

		TokenURL: types.String{Value: resp.GetTokenURL()},
		ClientID: types.String{Value: resp.GetClientId()},
		Scope:    types.String{Value: resp.GetScope()},
		Audience: types.String{Value: resp.GetAudience()},

		AgentName:     nullableStringToTfString(resp.AgentName),
		AgentUsername: nullableStringToTfString(resp.AgentUsername),
		DenialMax:     nullableInt32ToTfInt64(resp.DenialMax),
		LastScan:      types.String{Value: resp.GetLastScan()},
	}

	// Agent GUID
	state.Agent = nullableStringToTfString(resp.Agent)

	// AllowedRequesters
	if len(resp.AllowedRequesters) > 0 {
		state.AllowedRequesters = stringSliceToTfList(resp.AllowedRequesters)
	} else {
		state.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}
	}

	// Auth certificate metadata from response
	if resp.AuthCertificate != nil {
		state.AuthCertificateIssuedDN = types.String{Value: resp.AuthCertificate.GetIssuedDN()}
		state.AuthCertificateIssuerDN = types.String{Value: resp.AuthCertificate.GetIssuerDN()}
		state.AuthCertificateThumbprint = types.String{Value: resp.AuthCertificate.GetThumbprint()}
	}

	// Schedules
	if resp.FullScan != nil && resp.FullScan.Interval != nil {
		state.FullScanIntervalMinutes = types.Int64{Value: int64(resp.FullScan.Interval.GetMinutes())}
	} else {
		state.FullScanIntervalMinutes = types.Int64{Null: true}
	}
	if resp.IncrementalScan != nil && resp.IncrementalScan.Interval != nil {
		state.IncrementalScanIntervalMinutes = types.Int64{Value: int64(resp.IncrementalScan.Interval.GetMinutes())}
	} else {
		state.IncrementalScanIntervalMinutes = types.Int64{Null: true}
	}
	if resp.ThresholdCheck != nil && resp.ThresholdCheck.Interval != nil {
		state.ThresholdCheckIntervalMinutes = types.Int64{Value: int64(resp.ThresholdCheck.Interval.GetMinutes())}
	} else {
		state.ThresholdCheckIntervalMinutes = types.Int64{Null: true}
	}

	return state
}

func nullableInt32ToTfInt64(v v1.NullableInt32) types.Int64 {
	if v.Get() == nil {
		return types.Int64{Null: true}
	}
	return types.Int64{Value: int64(*v.Get())}
}

func nullableStringToTfString(v v1.NullableString) types.String {
	if v.Get() == nil {
		return types.String{Null: true}
	}
	return types.String{Value: *v.Get()}
}

func stringSliceToTfList(vals []string) types.List {
	return types.List{
		ElemType: types.StringType,
		Elems:    convertStringArrayToTerraform(vals),
	}
}

func buildCARequest(ctx context.Context, plan KeyfactorCertificateAuthority) v1.CertificateAuthoritiesCertificateAuthorityRequest {
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(int32(plan.CAType.Value))
	req := v1.CertificateAuthoritiesCertificateAuthorityRequest{
		CAType: &caType,
	}
	req.SetLogicalName(plan.LogicalName.Value)
	req.SetHostName(plan.HostName.Value)

	// Delegation & Connectivity
	setBoolIfKnown(&req, plan.Delegate, func(v bool) { req.SetDelegate(v) })
	setBoolIfKnown(&req, plan.DelegateEnrollment, func(v bool) { req.SetDelegateEnrollment(v) })
	setStringIfKnown(&req, plan.ForestRoot, func(v string) { req.SetForestRoot(v) })
	setStringIfKnown(&req, plan.ConfigurationTenant, func(v string) { req.SetConfigurationTenant(v) })
	setBoolIfKnown(&req, plan.Remote, func(v bool) { req.SetRemote(v) })
	setStringIfKnown(&req, plan.Agent, func(v string) { req.SetAgent(v) })
	setBoolIfKnown(&req, plan.Standalone, func(v bool) { req.SetStandalone(v) })
	setBoolIfKnown(&req, plan.UseCAConnector, func(v bool) { req.SetUseCAConnector(v) })
	setStringIfKnown(&req, plan.ConnectorPool, func(v string) { req.SetConnectorPool(v) })

	// Monitoring
	setBoolIfKnown(&req, plan.MonitorThresholds, func(v bool) { req.SetMonitorThresholds(v) })
	setNullableInt32IfKnown(&req, plan.IssuanceMax, func(v int32) { req.SetIssuanceMax(v) })
	setNullableInt32IfKnown(&req, plan.IssuanceMin, func(v int32) { req.SetIssuanceMin(v) })
	setNullableInt32IfKnown(&req, plan.FailureMax, func(v int32) { req.SetFailureMax(v) })

	// Enrollment & Policy
	setBoolIfKnown(&req, plan.RFCEnforcement, func(v bool) { req.SetRFCEnforcement(v) })
	setStringIfKnown(&req, plan.Properties, func(v string) { req.SetProperties(v) })
	if !plan.AllowedEnrollmentTypes.Null && !plan.AllowedEnrollmentTypes.Unknown {
		et := v1.CSSCMSCoreEnumsEnrollmentType(int32(plan.AllowedEnrollmentTypes.Value))
		req.AllowedEnrollmentTypes = &et
	}
	if !plan.KeyRetention.Null && !plan.KeyRetention.Unknown {
		kr := v1.CSSCMSCoreEnumsKeyRetentionPolicy(int32(plan.KeyRetention.Value))
		req.KeyRetention = &kr
	}
	setNullableInt32IfKnown(&req, plan.KeyRetentionDays, func(v int32) { req.SetKeyRetentionDays(v) })
	setBoolIfKnown(&req, plan.EnforceUniqueDN, func(v bool) { req.SetEnforceUniqueDN(v) })
	setBoolIfKnown(&req, plan.SubscriberTerms, func(v bool) { req.SetSubscriberTerms(v) })
	setBoolIfKnown(&req, plan.AllowOneClickRenewals, func(v bool) { req.SetAllowOneClickRenewals(v) })
	setBoolIfKnown(&req, plan.NewEndEntityOnRenewAndReissue, func(v bool) { req.SetNewEndEntityOnRenewAndReissue(v) })

	// Requesters
	setBoolIfKnown(&req, plan.UseAllowedRequesters, func(v bool) { req.SetUseAllowedRequesters(v) })
	if !plan.AllowedRequesters.Null && !plan.AllowedRequesters.Unknown {
		var requesters []string
		plan.AllowedRequesters.ElementsAs(ctx, &requesters, false)
		req.AllowedRequesters = requesters
	}

	// Explicit Credentials
	setBoolIfKnown(&req, plan.ExplicitCredentials, func(v bool) { req.SetExplicitCredentials(v) })
	setStringIfKnown(&req, plan.ExplicitUser, func(v string) { req.SetExplicitUser(v) })
	if !plan.ExplicitPassword.Null && !plan.ExplicitPassword.Unknown {
		secret := v1.CSSCMSDataModelModelsKeyfactorAPISecret{}
		secret.SetSecretValue(plan.ExplicitPassword.Value)
		req.ExplicitPassword = &secret
	}

	// Auth Certificate
	if !plan.AuthCertificate.Null && !plan.AuthCertificate.Unknown {
		secret := v1.CSSCMSDataModelModelsKeyfactorAPISecret{}
		secret.SetSecretValue(plan.AuthCertificate.Value)
		req.AuthCertificate = &secret
	}
	if !plan.AuthCertificatePassword.Null && !plan.AuthCertificatePassword.Unknown {
		secret := v1.CSSCMSDataModelModelsKeyfactorAPISecret{}
		secret.SetSecretValue(plan.AuthCertificatePassword.Value)
		req.AuthCertificatePassword = &secret
	}

	// OAuth
	setStringIfKnown(&req, plan.TokenURL, func(v string) { req.SetTokenURL(v) })
	setStringIfKnown(&req, plan.ClientID, func(v string) { req.SetClientId(v) })
	if !plan.ClientSecret.Null && !plan.ClientSecret.Unknown {
		secret := v1.CSSCMSDataModelModelsKeyfactorAPISecret{}
		secret.SetSecretValue(plan.ClientSecret.Value)
		req.ClientSecret = &secret
	}
	setStringIfKnown(&req, plan.Scope, func(v string) { req.SetScope(v) })
	setStringIfKnown(&req, plan.Audience, func(v string) { req.SetAudience(v) })

	// Schedules
	if !plan.FullScanIntervalMinutes.Null && !plan.FullScanIntervalMinutes.Unknown {
		minutes := int32(plan.FullScanIntervalMinutes.Value)
		interval := v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes}
		req.FullScan = &v1.KeyfactorCommonSchedulingKeyfactorSchedule{Interval: &interval}
	}
	if !plan.IncrementalScanIntervalMinutes.Null && !plan.IncrementalScanIntervalMinutes.Unknown {
		minutes := int32(plan.IncrementalScanIntervalMinutes.Value)
		interval := v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes}
		req.IncrementalScan = &v1.KeyfactorCommonSchedulingKeyfactorSchedule{Interval: &interval}
	}
	if !plan.ThresholdCheckIntervalMinutes.Null && !plan.ThresholdCheckIntervalMinutes.Unknown {
		minutes := int32(plan.ThresholdCheckIntervalMinutes.Value)
		interval := v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes}
		req.ThresholdCheck = &v1.KeyfactorCommonSchedulingKeyfactorSchedule{Interval: &interval}
	}

	return req
}

// setBoolIfKnown calls the setter only if the value is not null/unknown.
func setBoolIfKnown(_ interface{}, v types.Bool, setter func(bool)) {
	if !v.Null && !v.Unknown {
		setter(v.Value)
	}
}

// setStringIfKnown calls the setter only if the value is not null/unknown.
func setStringIfKnown(_ interface{}, v types.String, setter func(string)) {
	if !v.Null && !v.Unknown {
		setter(v.Value)
	}
}

// setNullableInt32IfKnown calls the setter only if the value is not null/unknown.
func setNullableInt32IfKnown(_ interface{}, v types.Int64, setter func(int32)) {
	if !v.Null && !v.Unknown {
		setter(int32(v.Value))
	}
}

// preserveSecrets copies write-only secret fields from source (plan or prior state) into the target state.
func preserveSecrets(target *KeyfactorCertificateAuthority, source KeyfactorCertificateAuthority) {
	target.ExplicitPassword = source.ExplicitPassword
	target.AuthCertificate = source.AuthCertificate
	target.AuthCertificatePassword = source.AuthCertificatePassword
	target.ClientSecret = source.ClientSecret
}

func (r resourceCertificateAuthority) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertificateAuthority.Create")

	var plan KeyfactorCertificateAuthority
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Creating certificate authority %q", plan.LogicalName.Value))

	createReq := buildCARequest(ctx, plan)

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi
	req := caAPI.NewCreateCertificateAuthorityRequest(ctx).CertificateAuthoritiesCertificateAuthorityRequest(createReq)
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error creating certificate authority.",
			fmt.Sprintf("Could not create certificate authority %q: %s. Details: %s", plan.LogicalName.Value, err.Error(), body),
		)
		return
	}

	state := caResponseToState(resp)
	preserveSecrets(&state, plan)

	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateAuthority.Create")
}

func (r resourceCertificateAuthority) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertificateAuthority.Read")

	var state KeyfactorCertificateAuthority
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate authority ID.",
			fmt.Sprintf("Could not parse certificate authority ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading certificate authority ID %d", id))

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi
	req := caAPI.NewGetCertificateAuthorityByIdRequest(ctx, int32(id))
	resp, httpResp, err := req.Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, fmt.Sprintf("Certificate authority %d not found, removing from state", id))
			response.State.RemoveResource(ctx)
			return
		}
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error reading certificate authority.",
			fmt.Sprintf("Could not read certificate authority %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	newState := caResponseToState(resp)
	preserveSecrets(&newState, state)

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateAuthority.Read")
}

func (r resourceCertificateAuthority) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertificateAuthority.Update")

	var plan KeyfactorCertificateAuthority
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var state KeyfactorCertificateAuthority
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate authority ID.",
			fmt.Sprintf("Could not parse certificate authority ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Updating certificate authority ID %d", id))

	updateReq := buildCARequest(ctx, plan)
	idInt32 := int32(id)
	updateReq.Id = &idInt32

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi
	req := caAPI.NewUpdateCertificateAuthorityRequest(ctx).CertificateAuthoritiesCertificateAuthorityRequest(updateReq)
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error updating certificate authority.",
			fmt.Sprintf("Could not update certificate authority %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	newState := caResponseToState(resp)
	preserveSecrets(&newState, plan)

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceCertificateAuthority.Update")
}

func (r resourceCertificateAuthority) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	LogFunctionEntry(ctx, "resourceCertificateAuthority.Delete")

	var state KeyfactorCertificateAuthority
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate authority ID.",
			fmt.Sprintf("Could not parse certificate authority ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting certificate authority ID %d", id))

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi
	req := caAPI.NewDeleteCertificateAuthorityByIdRequest(ctx, int32(id))
	httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error deleting certificate authority.",
			fmt.Sprintf("Could not delete certificate authority %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	LogFunctionExit(ctx, "resourceCertificateAuthority.Delete")
}

func (r resourceCertificateAuthority) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, fmt.Sprintf("ImportState called on certificate authority with ID %q", request.ID))

	id, err := strconv.Atoi(request.ID)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate authority ID.",
			fmt.Sprintf("Import ID must be an integer, got %q: %s", request.ID, err.Error()),
		)
		return
	}

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi
	req := caAPI.NewGetCertificateAuthorityByIdRequest(ctx, int32(id))
	resp, httpResp, err := req.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		response.Diagnostics.AddError(
			"Error importing certificate authority.",
			fmt.Sprintf("Could not read certificate authority %d: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	state := caResponseToState(resp)
	diags := response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
}

// normalizePropertiesJSON normalizes a JSON properties string for comparison.
func normalizePropertiesJSON(s string) string {
	if s == "" {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return s
	}
	b, _ := json.Marshal(m)
	return string(b)
}
