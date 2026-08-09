package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceCertificateAuthorityType struct{}

func (r resourceCertificateAuthorityType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Version:     1,
		Description: "Manages a Keyfactor Command Certificate Authority (CA). Secret fields (explicit_password, auth_certificate, auth_certificate_password, client_secret) are write-only — the server never returns plaintext values, so provider reads preserve configured values from state. The force_save flag bypasses the server-side connectivity test on create/update and is also write-only.",
		Attributes: map[string]tfsdk.Attribute{
			// --- Identity ---
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Integer ID of the certificate authority assigned by Keyfactor Command.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"logical_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string indicating the logical name of the certificate authority.",
			},
			"host_name": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string indicating the DNS hostname or URL of the certificate authority.",
			},
			"ca_type": {
				Type:          types.Int64Type,
				Required:      true,
				Description:   "An integer indicating the type of CA: 0 = DCOM (Microsoft ADCS) or 1 = HTTPS (e.g. EJBCA). Changing this forces a new resource.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},

			// --- Delegation & Connectivity ---
			"delegate": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether management interactions should be done in the context of the requesting user.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"delegate_enrollment": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether enrollment should be done in the context of the requesting user.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"forest_root": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A string indicating the forest root name or DNS domain name (retained for legacy purposes).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"configuration_tenant": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A string indicating the forest root name or DNS domain name for the certificate authority.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"remote": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether communications are done via a Keyfactor Universal Orchestrator.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"agent": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A string indicating the GUID of the Keyfactor Universal Orchestrator configured to manage the certificate authority.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"standalone": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether the certificate authority is a standalone CA.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"use_ca_connector": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether communications are done via a CA Connector Client.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"connector_pool": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A string indicating the name of the connector pool to use with the CA Connector Client.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Monitoring & Thresholds ---
			"monitor_thresholds": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether threshold monitoring is enabled with email alerts.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"issuance_max": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "An integer that sets the maximum number of certificates that can be issued before an alert is triggered.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"issuance_min": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "An integer that sets the minimum number of certificates that should be issued before an alert is triggered.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"failure_max": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "An integer that sets the maximum number of certificate requests that can fail before an alert is triggered.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Enrollment & Policy ---
			"rfc_enforcement": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether enrollments must include at least one DNS SAN.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"properties": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A string indicating additional properties, storing configuration for the Sync External Certificates option.",
				PlanModifiers: []tfsdk.AttributePlanModifier{normalizedJSONPropertiesModifier{}},
			},
			"allowed_enrollment_types": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "An integer that sets the type(s) of enrollment that are allowed through Keyfactor Command for the certificate authority: 0=none, 1=PFX, 2=CSR, 3=both. Requires standalone=true.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"key_retention": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "Key retention policy for the CA. Accepts the named form (Disabled, Indefinite, AfterExpiration, FromIssuance) or the equivalent integer string (\"0\"–\"3\"). Always stored in state as the named form.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Validators: []tfsdk.AttributeValidator{
					keyRetentionValidator{},
				},
			},
			"key_retention_days": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "An integer indicating the number of days for which to retain private keys before deletion.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"enforce_unique_dn": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether the unique DN requirement is enforced on the CA. Mutually exclusive with new_end_entity_on_renew_and_reissue=true.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"subscriber_terms": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether to add a checkbox forcing users to agree to terms.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allow_one_click_renewals": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether the CA will allow One-Click Renewal on certificates.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"new_end_entity_on_renew_and_reissue": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean setting whether renewal requests create new end entities. Required to be true for HTTPS CAs (ca_type=1). Mutually exclusive with enforce_unique_dn=true.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Enrollment Availability ---
			"use_for_enrollment": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Whether this CA is available for certificate enrollment.",
			},

			// --- Certificate Cleanup ---
			"certificate_cleanup_enabled": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Whether certificate cleanup is enabled for this CA.",
			},
			"delete_with_archived_key": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Whether to delete the certificate when its archived key is deleted.",
			},
			"time_after_expiration": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Time value after expiration before cleanup occurs. Used with time_after_expiration_units.",
			},
			"time_after_expiration_units": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
				Description:   "Units for time_after_expiration: 0=Days, 1=Weeks, 2=Months.",
			},

			// --- Requesters (standalone CAs only) ---
			"use_allowed_requesters": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether the allowed requesters option is enabled. Applies to standalone CAs only.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"allowed_requesters": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				Computed:      true,
				Description:   "An array of strings indicating Keyfactor Command security roles that are allowed to enroll for certificates via Keyfactor Command for this CA. Applies to standalone CAs only. Write-only: not returned by the server GET; preserved from plan/state.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Explicit Credentials (write-only secrets) ---
			"explicit_credentials": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "A Boolean that sets whether explicit credentials are enabled for this certificate authority.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"explicit_user": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "A string indicating the username in DOMAIN\\username format for service account credentials.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"explicit_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "An object indicating the password information to use for authentication with explicit_user. Write-only; cannot be read back from the server. Unlike this resource's other Optional+Computed attributes, this field is Optional only (not Computed) and is NOT preserved on omission: removing it from config clears the stored credential server-side on the next apply, since the full-replace update omits it from the request entirely.",
			},

			// --- Auth Certificate (write-only) ---
			"auth_certificate": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "An object containing information about the client certificate used to provide authentication to the HTTPS CA. Write-only. Unlike this resource's other Optional+Computed attributes, this field is Optional only (not Computed) and is NOT preserved on omission: removing it from config clears the stored credential server-side on the next apply, since the full-replace update omits it from the request entirely.",
			},
			"auth_certificate_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "An object indicating the password for the certificate to use to authenticate to the HTTPS CA. Write-only. Unlike this resource's other Optional+Computed attributes, this field is Optional only (not Computed) and is NOT preserved on omission: removing it from config clears the stored credential server-side on the next apply, since the full-replace update omits it from the request entirely.",
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

			// --- OAuth Config (HTTPS CAs only) ---
			"token_url": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "For HTTPS CAs, a string indicating the bearer token URL of the identity provider.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"client_id": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "For HTTPS CAs, a string specifying the client ID used to authenticate when OAuth authentication is selected.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"client_secret": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "For HTTPS CAs, an object indicating the secret for the client used to authenticate. Write-only; cannot be read back from the server. Unlike this resource's other Optional+Computed attributes, this field is Optional only (not Computed) and is NOT preserved on omission: removing it from config clears the stored credential server-side on the next apply, since the full-replace update omits it from the request entirely.",
			},
			"scope": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "For HTTPS CAs, a string indicating scopes included in token requests, separated by spaces.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"audience": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "For HTTPS CAs, a string specifying the audience to include in token requests to the identity provider.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Schedules (flat interval minutes, or daily time-of-day) ---
			// Command represents each of these three schedules as one of several mutually
			// exclusive variants (Interval, Daily, Weekly, Monthly, ExactlyOnce, Immediate);
			// this provider currently models the two variants seen in practice, Interval and
			// Daily. Setting both the *_interval_minutes and *_daily_time attribute for the
			// same schedule at once is invalid and rejected at plan time (ValidateConfig).
			"full_scan_interval_minutes": {
				Type:        types.Int64Type,
				Optional:    true,
				Computed:    true,
				Description: "Interval in minutes for the full synchronization schedule of this certificate authority. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Mutually exclusive with full_scan_daily_time. Warning: creates a Windows Task Scheduler entry for DCOM CAs that blocks CA deletion.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					scheduleSiblingModifier{siblingPath: path.Root("full_scan_daily_time"), nullValue: types.Int64{Null: true}},
				},
			},
			"full_scan_daily_time": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), that sets a once-daily full synchronization schedule for this certificate authority. Mutually exclusive with full_scan_interval_minutes. Command only preserves the time-of-day component and rewrites the date anchor server-side, so only \"HH:MM:SS\" is accepted -- a full timestamp can never round-trip.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					scheduleSiblingModifier{siblingPath: path.Root("full_scan_interval_minutes"), nullValue: types.String{Null: true}},
				},
			},
			"incremental_scan_interval_minutes": {
				Type:        types.Int64Type,
				Optional:    true,
				Computed:    true,
				Description: "Interval in minutes for the incremental synchronization schedule of this certificate authority. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Mutually exclusive with incremental_scan_daily_time. Warning: creates a Windows Task Scheduler entry for DCOM CAs that blocks CA deletion.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					scheduleSiblingModifier{siblingPath: path.Root("incremental_scan_daily_time"), nullValue: types.Int64{Null: true}},
				},
			},
			"incremental_scan_daily_time": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), that sets a once-daily incremental synchronization schedule for this certificate authority. Mutually exclusive with incremental_scan_interval_minutes. Command only preserves the time-of-day component and rewrites the date anchor server-side, so only \"HH:MM:SS\" is accepted -- a full timestamp can never round-trip.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					scheduleSiblingModifier{siblingPath: path.Root("incremental_scan_interval_minutes"), nullValue: types.String{Null: true}},
				},
			},
			"threshold_check_interval_minutes": {
				Type:        types.Int64Type,
				Optional:    true,
				Computed:    true,
				Description: "Interval in minutes for the threshold monitoring check schedule on this CA. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Mutually exclusive with threshold_check_daily_time.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					scheduleSiblingModifier{siblingPath: path.Root("threshold_check_daily_time"), nullValue: types.Int64{Null: true}},
				},
			},
			"threshold_check_daily_time": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), that sets a once-daily threshold monitoring check schedule on this CA. Mutually exclusive with threshold_check_interval_minutes. Command only preserves the time-of-day component and rewrites the date anchor server-side, so only \"HH:MM:SS\" is accepted -- a full timestamp can never round-trip.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					scheduleSiblingModifier{siblingPath: path.Root("threshold_check_interval_minutes"), nullValue: types.String{Null: true}},
				},
			},

			// --- Write-only control flags ---
			"force_save": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "A Boolean indicating whether to save the CA record even if the CA connectivity test fails. Useful when provisioning a CA record before the CA server is reachable. Write-only — not returned by the server; preserved from config/state after reads.",
			},

			// --- Read-only ---
			"agent_name": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Name of the orchestrator agent managing this CA (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"agent_username": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Username of the orchestrator agent managing this CA (read-only).",
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
				Description:   "A string indicating the date in UTC on which a synchronization was last performed (read-only).",
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
	KeyRetention                  types.String `tfsdk:"key_retention"`
	KeyRetentionDays              types.Int64  `tfsdk:"key_retention_days"`
	EnforceUniqueDN               types.Bool   `tfsdk:"enforce_unique_dn"`
	SubscriberTerms               types.Bool   `tfsdk:"subscriber_terms"`
	AllowOneClickRenewals         types.Bool   `tfsdk:"allow_one_click_renewals"`
	NewEndEntityOnRenewAndReissue types.Bool   `tfsdk:"new_end_entity_on_renew_and_reissue"`

	// Enrollment Availability
	UseForEnrollment types.Bool `tfsdk:"use_for_enrollment"`

	// Certificate Cleanup
	CertificateCleanupEnabled types.Bool  `tfsdk:"certificate_cleanup_enabled"`
	DeleteWithArchivedKey     types.Bool  `tfsdk:"delete_with_archived_key"`
	TimeAfterExpiration       types.Int64 `tfsdk:"time_after_expiration"`
	TimeAfterExpirationUnits  types.Int64 `tfsdk:"time_after_expiration_units"`

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

	// Schedules. Each of the three below can be represented server-side as either
	// an Interval schedule or a Daily (time-of-day) schedule -- mutually exclusive
	// per pair, enforced by ValidateConfig.
	FullScanIntervalMinutes        types.Int64  `tfsdk:"full_scan_interval_minutes"`
	FullScanDailyTime              types.String `tfsdk:"full_scan_daily_time"`
	IncrementalScanIntervalMinutes types.Int64  `tfsdk:"incremental_scan_interval_minutes"`
	IncrementalScanDailyTime       types.String `tfsdk:"incremental_scan_daily_time"`
	ThresholdCheckIntervalMinutes  types.Int64  `tfsdk:"threshold_check_interval_minutes"`
	ThresholdCheckDailyTime        types.String `tfsdk:"threshold_check_daily_time"`

	// Write-only control flags
	ForceSave types.Bool `tfsdk:"force_save"`

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

		// Use nil-safe helpers for all pointer fields. GetXxx() returns the Go zero
		// value (false/0/"") when the server omits a field; that zero value would then
		// be sent on subsequent PUTs, silently overwriting server settings. Using
		// boolPtrToTfBool / enrollmentTypePtrToTfInt64 / nullableStringToTfString
		// returns Null instead, so setBoolIfKnown/setStringIfKnown skips those fields.
		Delegate:            boolPtrToTfBool(resp.Delegate),
		DelegateEnrollment:  boolPtrToTfBool(resp.DelegateEnrollment),
		ForestRoot:          nullableStringToTfString(resp.ForestRoot),
		ConfigurationTenant: nullableStringToTfString(resp.ConfigurationTenant),
		Remote:              boolPtrToTfBool(resp.Remote),
		Standalone:          boolPtrToTfBool(resp.Standalone),
		UseCAConnector:      boolPtrToTfBool(resp.UseCAConnector),
		ConnectorPool:       nullableStringToTfString(resp.ConnectorPool),

		MonitorThresholds: boolPtrToTfBool(resp.MonitorThresholds),
		IssuanceMax:       nullableInt32ToTfInt64(resp.IssuanceMax),
		IssuanceMin:       nullableInt32ToTfInt64(resp.IssuanceMin),
		FailureMax:        nullableInt32ToTfInt64(resp.FailureMax),

		RFCEnforcement:                boolPtrToTfBool(resp.RFCEnforcement),
		Properties:                    nullableStringToTfString(resp.Properties),
		AllowedEnrollmentTypes:        enrollmentTypePtrToTfInt64(resp.AllowedEnrollmentTypes),
		KeyRetention:                  keyRetentionIntToTfString(resp.KeyRetention),
		KeyRetentionDays:              nullableInt32ToTfInt64(resp.KeyRetentionDays),
		EnforceUniqueDN:               boolPtrToTfBool(resp.EnforceUniqueDN),
		SubscriberTerms:               boolPtrToTfBool(resp.SubscriberTerms),
		AllowOneClickRenewals:         boolPtrToTfBool(resp.AllowOneClickRenewals),
		NewEndEntityOnRenewAndReissue: boolPtrToTfBool(resp.NewEndEntityOnRenewAndReissue),

		UseForEnrollment:          boolPtrToTfBool(resp.UseForEnrollment),
		CertificateCleanupEnabled: nullableBoolToTfBool(resp.CertificateCleanupEnabled),
		DeleteWithArchivedKey:     nullableBoolToTfBool(resp.DeleteWithArchivedKey),
		TimeAfterExpiration:       nullableInt32ToTfInt64(resp.TimeAfterExpiration),
		TimeAfterExpirationUnits:  cleanupTimeUnitsPtrToTfInt64(resp.TimeAfterExpirationUnits),

		UseAllowedRequesters: boolPtrToTfBool(resp.UseAllowedRequesters),

		ExplicitCredentials: boolPtrToTfBool(resp.ExplicitCredentials),
		ExplicitUser:        nullableStringToTfString(resp.ExplicitUser),

		TokenURL: nullableStringToTfString(resp.TokenURL),
		ClientID: nullableStringToTfString(resp.ClientId),
		Scope:    nullableStringToTfString(resp.Scope),
		Audience: nullableStringToTfString(resp.Audience),

		AgentName:     nullableStringToTfString(resp.AgentName),
		AgentUsername: nullableStringToTfString(resp.AgentUsername),
		DenialMax:     nullableInt32ToTfInt64(resp.DenialMax),
		LastScan:      nullableStringToTfString(resp.LastScan),
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
	} else {
		state.AuthCertificateIssuedDN = types.String{Null: true}
		state.AuthCertificateIssuerDN = types.String{Null: true}
		state.AuthCertificateThumbprint = types.String{Null: true}
	}

	// Schedules. Command represents FullScan/IncrementalScan/ThresholdCheck as a
	// KeyfactorSchedule that can be Interval-shaped OR Daily-shaped (among other
	// variants not yet modeled here: Weekly/Monthly/ExactlyOnce/Immediate -- see
	// GH issue #185 for the Weekly case specifically). A Daily-shaped schedule
	// must NOT collapse to Null here: Null is indistinguishable from "no schedule
	// configured at all," and buildCARequest would then omit the field entirely
	// on the next PUT, which Command's full-replace semantics interpret as
	// "clear this schedule" -- silently wiping a real, live Daily scan schedule
	// server-side on every subsequent apply.
	state.FullScanIntervalMinutes, state.FullScanDailyTime = scheduleToState(resp.FullScan)
	state.IncrementalScanIntervalMinutes, state.IncrementalScanDailyTime = scheduleToState(resp.IncrementalScan)
	state.ThresholdCheckIntervalMinutes, state.ThresholdCheckDailyTime = scheduleToState(resp.ThresholdCheck)

	// force_save is write-only; always null from server reads.
	state.ForceSave = types.Bool{Null: true}

	return state
}

// caDailyTimeLayout is the Go reference-time layout for the *_daily_time
// attributes: a bare UTC time-of-day, "HH:MM:SS" (e.g. "07:00:00"). Command's
// GET echoes back the exact time-of-day it was given but rewrites the date
// component to the current date (confirmed live against the Command API), so
// any date/offset information in the wire format would be pure noise that
// can never round-trip -- only the time-of-day is meaningful. A full RFC3339
// timestamp (the original, pre-fix wire format) can therefore never survive
// a Read/Create/Update response comparison intact: every apply would see a
// "changed" date component even though nothing about the schedule actually
// changed. See GH issue #193 / dev-harness Gap A.
const caDailyTimeLayout = "15:04:05"

// scheduleToState converts a Command KeyfactorSchedule (as returned for FullScan,
// IncrementalScan, or ThresholdCheck) into the pair of Terraform attribute values used
// to represent it: an Interval-shaped *_interval_minutes value and a Daily-shaped
// *_daily_time value. Command's schedule is a tagged union -- at most one variant is
// populated at a time -- so at most one of the two returned values will be non-null.
//
// Both values come back Null when the schedule is nil (no schedule configured) or
// when it holds a variant this provider does not yet model (Weekly, Monthly,
// ExactlyOnce, Immediate). That is a known, narrower gap than the Daily-collapse bug
// this function fixes: an unmodeled variant still reads as "no schedule," so an
// Update() that doesn't touch this attribute pair would omit it from the PUT and
// clear it -- see GH issue #185 for Weekly specifically, which the vendored SDK
// cannot even deserialize (SystemDayOfWeek expects an int; Command returns day-name
// strings), so a targeted fix would need to land in the SDK, not here.
func scheduleToState(sched *v1.KeyfactorCommonSchedulingKeyfactorSchedule) (types.Int64, types.String) {
	interval := types.Int64{Null: true}
	daily := types.String{Null: true}
	if sched == nil {
		return interval, daily
	}
	if sched.Interval != nil {
		interval = types.Int64{Value: int64(sched.Interval.GetMinutes())}
	}
	if sched.Daily != nil && sched.Daily.Time != nil {
		daily = types.String{Value: sched.Daily.Time.UTC().Format(caDailyTimeLayout)}
	}
	return interval, daily
}

// buildSchedule constructs a Command KeyfactorSchedule from a plan/state pair of
// Interval and Daily attribute values. The two representations are mutually exclusive
// (enforced at plan time by resourceCertificateAuthority.ValidateConfig), so only one
// of intervalMinutes/dailyTime is expected to be known; if both are somehow known,
// intervalMinutes takes precedence. Returns (nil, nil) when neither is known, matching
// the "omit the field from the request" semantics buildCARequest relies on elsewhere.
// dailyTime is parsed as a bare UTC time-of-day (caDailyTimeLayout) and anchored to a
// fixed, arbitrary date -- Command rewrites the date component to the current date
// server-side regardless of what is sent (confirmed live), so a fixed anchor keeps
// this function deterministic without affecting the schedule actually applied.
func buildSchedule(intervalMinutes types.Int64, dailyTime types.String) (*v1.KeyfactorCommonSchedulingKeyfactorSchedule, error) {
	if !intervalMinutes.Null && !intervalMinutes.Unknown {
		minutes := int32(intervalMinutes.Value)
		return &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Interval: &v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes},
		}, nil
	}
	if !dailyTime.Null && !dailyTime.Unknown {
		t, err := time.Parse(caDailyTimeLayout, dailyTime.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid daily time %q: %w", dailyTime.Value, err)
		}
		anchored := time.Date(2000, 1, 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		return &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Daily: &v1.KeyfactorCommonSchedulingModelsTimeModel{Time: &anchored},
		}, nil
	}
	return nil, nil
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

// boolPtrToTfBool converts a *bool pointer from the SDK response to a types.Bool.
// When the server omits a field (nil pointer), returns Null so that subsequent PUTs
// do not send a zero-value false and inadvertently overwrite server settings.
func boolPtrToTfBool(v *bool) types.Bool {
	if v == nil {
		return types.Bool{Null: true}
	}
	return types.Bool{Value: *v}
}

// enrollmentTypePtrToTfInt64 converts a *CSSCMSCoreEnumsEnrollmentType pointer to types.Int64.
// Nil (server field absent) becomes Null so the value is not sent on PUT.
func enrollmentTypePtrToTfInt64(v *v1.CSSCMSCoreEnumsEnrollmentType) types.Int64 {
	if v == nil {
		return types.Int64{Null: true}
	}
	return types.Int64{Value: int64(*v)}
}

// keyRetentionPtrToTfInt64 converts a *CSSCMSCoreEnumsKeyRetentionPolicy pointer to types.Int64.
// Nil (server field absent) becomes Null so the value is not sent on PUT.
func keyRetentionPtrToTfInt64(v *v1.CSSCMSCoreEnumsKeyRetentionPolicy) types.Int64 {
	if v == nil {
		return types.Int64{Null: true}
	}
	return types.Int64{Value: int64(*v)}
}

// nullableBoolToTfBool converts a NullableBool from the SDK response to a types.Bool.
// When the server omits the field (not set / nil), returns Null.
func nullableBoolToTfBool(v v1.NullableBool) types.Bool {
	if v.Get() == nil {
		return types.Bool{Null: true}
	}
	return types.Bool{Value: *v.Get()}
}

// cleanupTimeUnitsPtrToTfInt64 converts a *CSSCMSDataModelEnumsCertificateCleanupTimeUnits pointer to types.Int64.
// Nil (server field absent) becomes Null so the value is not sent on PUT.
func cleanupTimeUnitsPtrToTfInt64(v *v1.CSSCMSDataModelEnumsCertificateCleanupTimeUnits) types.Int64 {
	if v == nil {
		return types.Int64{Null: true}
	}
	return types.Int64{Value: int64(*v)}
}

func stringSliceToTfList(vals []string) types.List {
	return types.List{
		ElemType: types.StringType,
		Elems:    convertStringArrayToTerraform(vals),
	}
}

func buildCARequest(ctx context.Context, plan KeyfactorCertificateAuthority) (v1.CertificateAuthoritiesCertificateAuthorityRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
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
		if intVal, ok := keyRetentionNameToInt[plan.KeyRetention.Value]; ok {
			kr := v1.CSSCMSCoreEnumsKeyRetentionPolicy(intVal)
			req.KeyRetention = &kr
		}
	}
	setNullableInt32IfKnown(&req, plan.KeyRetentionDays, func(v int32) { req.SetKeyRetentionDays(v) })
	setBoolIfKnown(&req, plan.EnforceUniqueDN, func(v bool) { req.SetEnforceUniqueDN(v) })
	setBoolIfKnown(&req, plan.SubscriberTerms, func(v bool) { req.SetSubscriberTerms(v) })
	setBoolIfKnown(&req, plan.AllowOneClickRenewals, func(v bool) { req.SetAllowOneClickRenewals(v) })
	setBoolIfKnown(&req, plan.NewEndEntityOnRenewAndReissue, func(v bool) { req.SetNewEndEntityOnRenewAndReissue(v) })

	// Enrollment Availability
	setBoolIfKnown(&req, plan.UseForEnrollment, func(v bool) { req.SetUseForEnrollment(v) })

	// Certificate Cleanup
	setNullableBoolIfKnown(&req, plan.CertificateCleanupEnabled, func(v bool) { req.SetCertificateCleanupEnabled(v) })
	setNullableBoolIfKnown(&req, plan.DeleteWithArchivedKey, func(v bool) { req.SetDeleteWithArchivedKey(v) })
	setNullableInt32IfKnown(&req, plan.TimeAfterExpiration, func(v int32) { req.SetTimeAfterExpiration(v) })
	if !plan.TimeAfterExpirationUnits.Null && !plan.TimeAfterExpirationUnits.Unknown {
		units := v1.CSSCMSDataModelEnumsCertificateCleanupTimeUnits(int32(plan.TimeAfterExpirationUnits.Value))
		req.TimeAfterExpirationUnits = &units
	}

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

	// Schedules. Each of FullScan/IncrementalScan/ThresholdCheck can be represented
	// as either an Interval or a Daily schedule (mutually exclusive per pair,
	// enforced by ValidateConfig at plan time). buildSchedule returns nil for a
	// pair that is entirely null/unknown, which -- per Command's full-replace PUT
	// semantics -- omits the field from the request and clears it server-side;
	// preserveCAUpdateFields (called from Update before this function runs) is
	// what prevents that from happening on an update that simply didn't declare
	// the attribute.
	fullScan, err := buildSchedule(plan.FullScanIntervalMinutes, plan.FullScanDailyTime)
	if err != nil {
		diags.AddAttributeError(path.Root("full_scan_daily_time"), "Invalid full_scan schedule", err.Error())
	} else {
		req.FullScan = fullScan
	}
	incrementalScan, err := buildSchedule(plan.IncrementalScanIntervalMinutes, plan.IncrementalScanDailyTime)
	if err != nil {
		diags.AddAttributeError(path.Root("incremental_scan_daily_time"), "Invalid incremental_scan schedule", err.Error())
	} else {
		req.IncrementalScan = incrementalScan
	}
	thresholdCheck, err := buildSchedule(plan.ThresholdCheckIntervalMinutes, plan.ThresholdCheckDailyTime)
	if err != nil {
		diags.AddAttributeError(path.Root("threshold_check_daily_time"), "Invalid threshold_check schedule", err.Error())
	} else {
		req.ThresholdCheck = thresholdCheck
	}

	// Command rejects a request that carries populated fields for both CA auth
	// variants (OAuth vs. client-certificate) at once. Since buildCARequest is
	// the single payload constructor shared by Create, Update, and Delete's
	// clear-schedules-before-delete fallback, deriving and stripping the unused
	// variant here -- rather than in each caller -- guarantees all three agree
	// on which variant is active. See clearAuthVariant.
	clearAuthVariant(&req, plan)

	return req, diags
}

// isKnownNonEmptyString reports whether a types.String plan/state value is
// both known (not Null/Unknown) and non-empty. Used by clearAuthVariant to
// distinguish a genuinely configured credential from a zero-value string.
func isKnownNonEmptyString(v types.String) bool {
	return !v.Null && !v.Unknown && v.Value != ""
}

// clearAuthVariant strips whichever CA authentication variant -- OAuth or
// client-certificate -- is NOT actually in use from an already-built request,
// so the payload never carries populated fields for both at once. Command
// rejects such a request outright: "Fields for OAuth and Client Certificate
// Authentication cannot both be provided for the same CA."
//
// token_url, client_id, scope, and audience are Optional+Computed with a
// UseStateForUnknown plan modifier (see the schema above). Once a
// client-certificate-auth CA's first Read populates them with the server's
// non-OAuth zero value -- an empty string, not a null pointer; see
// caResponseToState's use of nullableStringToTfString -- that empty string is
// carried forward into every later plan/state and, without this function,
// would be echoed back into every subsequent write via
// req.SetTokenURL("")/req.SetClientId(""). Those setters mark the underlying
// NullableString as explicitly "set," which is indistinguishable on the wire
// from a genuinely configured empty value -- Command's server-side check does
// not require the value to be non-empty, only present. auth_certificate and
// auth_certificate_password, by contrast, are Optional but NOT Computed, so
// they directly reflect config and are only genuinely populated when the user
// has configured client-certificate auth.
//
// Called from buildCARequest itself -- the single payload constructor shared
// by Create, Update, and Delete's clear-schedules-before-delete fallback --
// so all three derive the active auth variant identically; there is no
// separate per-caller copy of this logic that could drift out of sync.
// Fixes #194.
func clearAuthVariant(req *v1.CertificateAuthoritiesCertificateAuthorityRequest, plan KeyfactorCertificateAuthority) {
	hasCertAuth := isKnownNonEmptyString(plan.AuthCertificate)
	hasOAuth := isKnownNonEmptyString(plan.ClientID) || isKnownNonEmptyString(plan.TokenURL)

	clearOAuthFields := func() {
		req.UnsetTokenURL()
		req.UnsetClientId()
		req.ClientSecret = nil
		req.UnsetScope()
		req.UnsetAudience()
	}
	clearCertAuthFields := func() {
		req.AuthCertificate = nil
		req.AuthCertificatePassword = nil
	}

	switch {
	case hasCertAuth:
		// Client-certificate auth is in use: never echo OAuth fields, even a
		// stale empty-string value carried forward from a prior Computed read.
		clearOAuthFields()
	case hasOAuth:
		// OAuth is in use: never send client-certificate auth fields. These are
		// normally already nil here since auth_certificate is not Computed, but
		// clearing them keeps this function symmetric and defensive against
		// future schema changes.
		clearCertAuthFields()
	default:
		// Neither variant is genuinely configured (e.g. a DCOM CA, or an HTTPS
		// CA authenticating via explicit/agent credentials): don't echo stale
		// empty-string OAuth fields either.
		clearOAuthFields()
		clearCertAuthFields()
	}
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

// setNullableBoolIfKnown calls the setter only if the value is not null/unknown.
// Used for SDK NullableBool fields (e.g., CertificateCleanupEnabled, DeleteWithArchivedKey).
func setNullableBoolIfKnown(_ interface{}, v types.Bool, setter func(bool)) {
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
	target.ForceSave = source.ForceSave
	// AllowedRequesters is not returned by the server GET; preserve from plan/state.
	// Only copy when the value is known (not null AND not unknown) to avoid
	// propagating Unknown into state during Create where there is no prior state.
	if !source.AllowedRequesters.Null && !source.AllowedRequesters.Unknown {
		target.AllowedRequesters = source.AllowedRequesters
	}
}

// declaredInConfig reports whether an attribute was actually written in the
// user's HCL config, as opposed to being merely Null after plan modifiers ran.
// request.Config is never touched by plan modifiers (unlike request.Plan), so
// it is the only signal available in Update() that survives a plan modifier
// resolving an "undeclared" attribute to something other than a literal Null
// -- which is exactly what happens here: an undeclared *_interval_minutes or
// *_daily_time is resolved by UseStateForUnknown to the PRIOR STATE value
// (usually non-null), not to Null, so checking plan.X.Null would almost never
// fire and would miss the very case preserveCAUpdateFields exists to handle.
func declaredInConfig(v interface{ IsNull() bool }) bool {
	return !v.IsNull()
}

// preserveCAUpdateFields reconciles the three schedule attribute pairs
// (full_scan, incremental_scan, threshold_check -- each Interval XOR Daily) on
// plan against what the user actually declared in config, for an Update().
//
// Each pair's *_interval_minutes and *_daily_time attributes are
// Optional+Computed with a UseStateForUnknown plan modifier, so the
// terraform-plugin-framework automatically resolves an UNDECLARED attribute's
// plan value to that attribute's prior STATE value before this function ever
// runs. That default behavior is correct when NEITHER member of a pair is
// declared in config (there's nothing left to reconcile: both plan values
// already equal their prior state values). It is WRONG when the user is
// switching schedule variants -- e.g. declaring full_scan_daily_time for the
// first time while leaving full_scan_interval_minutes undeclared. In that
// case UseStateForUnknown independently carries the OLD
// full_scan_interval_minutes value forward from state, so without this
// function the plan would end up with BOTH members of the pair non-null at
// once: the newly-declared Daily value AND the stale Interval value
// resurrected from state. buildSchedule would have to arbitrarily pick one,
// and Read after apply would return only the Daily-shaped schedule, nulling
// the resurrected Interval value back out of state -- an inconsistent result
// after apply.
//
// Reconciliation, per pair, keyed on config (not plan):
//   - Neither variant declared in config: leave plan untouched. UseStateForUnknown
//     already carried the correct prior-state value(s) forward.
//   - Exactly one variant declared in config: that declared variant is the new,
//     authoritative one. Force the OTHER (sibling) attribute to explicit Null on
//     the plan so it does not resurrect a stale value from state and does not
//     reach buildSchedule.
//   - Both declared in config: rejected earlier by ValidateConfig; not reachable
//     here in practice, but this function is a no-op for that case regardless
//     (each branch below only fires when exactly one side is declared).
func preserveCAUpdateFields(plan *KeyfactorCertificateAuthority, config KeyfactorCertificateAuthority) {
	reconcileSchedule := func(planInterval *types.Int64, planDaily *types.String, configInterval types.Int64, configDaily types.String) {
		intervalDeclared := declaredInConfig(configInterval)
		dailyDeclared := declaredInConfig(configDaily)
		switch {
		case intervalDeclared && !dailyDeclared:
			*planDaily = types.String{Null: true}
		case dailyDeclared && !intervalDeclared:
			*planInterval = types.Int64{Null: true}
		}
		// Neither declared, or (unreachable) both declared: leave plan as-is.
	}
	reconcileSchedule(&plan.FullScanIntervalMinutes, &plan.FullScanDailyTime, config.FullScanIntervalMinutes, config.FullScanDailyTime)
	reconcileSchedule(&plan.IncrementalScanIntervalMinutes, &plan.IncrementalScanDailyTime, config.IncrementalScanIntervalMinutes, config.IncrementalScanDailyTime)
	reconcileSchedule(&plan.ThresholdCheckIntervalMinutes, &plan.ThresholdCheckDailyTime, config.ThresholdCheckIntervalMinutes, config.ThresholdCheckDailyTime)
}

// scheduleSiblingModifier is the plan-time half of schedule variant-switch
// reconciliation (the other half is preserveCAUpdateFields, which only runs
// inside Update() -- see its doc comment for why that alone is NOT
// sufficient). Full-review round 1 finding #2:
//
// All six schedule attributes were Optional+Computed with only a bare
// tfsdk.UseStateForUnknown(). Consider a CA in state with
// full_scan_interval_minutes=60 (no full_scan_daily_time), where config
// switches to declaring only full_scan_daily_time: core's proposed plan
// keeps full_scan_interval_minutes at its prior state value BEFORE any
// plan modifier runs (Computed + null config -> marked Unknown), and a bare
// UseStateForUnknown then pins that Unknown straight back to the OLD known
// value (60) -- it has no way to know a sibling attribute is taking over.
// The recorded plan therefore has BOTH full_scan_interval_minutes=60 AND
// full_scan_daily_time="<new>" at once. preserveCAUpdateFields nulls the
// stale sibling, but only in Update()'s own LOCAL plan copy, long after
// PlanResourceChange already recorded the plan Terraform core will compare
// the final applied state against -- so the update succeeds server-side,
// but Terraform then hard-fails with "Provider produced inconsistent result
// after apply: .full_scan_interval_minutes: was cty.NumberIntVal(60), but
// now null" on every single variant switch, in both directions, for all
// three pairs.
//
// This modifier fixes it AT PLAN TIME by reading the SIBLING attribute's
// CONFIG value (the same req.Config.GetAttribute pattern
// displayNameFollowsFriendlyNameModifier uses to read a related attribute's
// config) before falling back to UseStateForUnknown semantics:
//   - Sibling declared (known) in config: this attribute's own config must be
//     null (Modify only ever reaches the Unknown-plan branch for a
//     null-configured Computed attribute), so the sibling is taking over --
//     null this attribute's plan instead of resurrecting its stale prior
//     state value.
//   - Sibling itself Unknown (depends on some other not-yet-known value):
//     conservatively leave this attribute Unknown too, deferring the
//     decision to apply time rather than guessing.
//   - Sibling also null/undeclared: ordinary UseStateForUnknown semantics --
//     carry this attribute's own prior state value forward.
//
// preserveCAUpdateFields remains in place as a defensive no-op / safety net
// for the neither-variant-declared case it already handled correctly; with
// this modifier the variant-switch case it existed for is resolved before
// Update() ever runs.
//
// This hand-ports the concept (not the code) of PR #182's unmerged
// `pairedWith` modifier on fix/ca-schedule-daily-variant.
type scheduleSiblingModifier struct {
	siblingPath path.Path
	nullValue   attr.Value
}

func (m scheduleSiblingModifier) Description(_ context.Context) string {
	return "Uses the prior state value unless the sibling schedule variant is declared in config, in which case the plan is nulled so the new variant can take over cleanly."
}

func (m scheduleSiblingModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m scheduleSiblingModifier) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil || req.AttributeConfig == nil {
		return
	}
	if !resp.AttributePlan.IsUnknown() {
		return
	}
	if req.AttributeConfig.IsUnknown() {
		return
	}

	var siblingConfig attr.Value
	if diags := req.Config.GetAttribute(ctx, m.siblingPath, &siblingConfig); diags.HasError() {
		// Conservative fallback: behave like plain UseStateForUnknown.
		if !req.AttributeState.IsUnknown() {
			resp.AttributePlan = req.AttributeState
		}
		return
	}

	switch {
	case siblingConfig == nil:
		// No usable sibling value -- fall through to default
		// UseStateForUnknown semantics below.
	case siblingConfig.IsUnknown():
		// Cannot yet tell whether the sibling variant is taking over (it
		// depends on some other not-yet-known value this apply) -- be
		// conservative and leave this attribute Unknown too, rather than
		// guessing and risking the same inconsistent-result class this
		// modifier exists to prevent.
		return
	case !siblingConfig.IsNull():
		// Sibling variant is declared in config and taking over this apply.
		// This attribute's own config is null (guaranteed by reaching this
		// point: AttributeConfig isn't itself Unknown, and a Computed
		// attribute's plan only becomes Unknown when its own config is
		// null) -- so do not resurrect this attribute's stale prior-state
		// value onto the plan.
		resp.AttributePlan = m.nullValue
		return
	}

	// Sibling also null/undeclared: ordinary UseStateForUnknown semantics.
	if req.AttributeState.IsUnknown() {
		return
	}
	resp.AttributePlan = req.AttributeState
}

// ValidateConfig rejects two classes of invalid schedule configuration before
// plan/apply ever runs: declaring both the Interval and Daily variant of the
// same schedule pair at once (ambiguous -- buildSchedule would otherwise have
// to silently pick one), and declaring a *_daily_time value that isn't a
// parseable RFC3339 timestamp (buildSchedule would otherwise fail deep inside
// Create/Update with a less actionable error).
func (r resourceCertificateAuthority) ValidateConfig(ctx context.Context, request tfsdk.ValidateResourceConfigRequest, response *tfsdk.ValidateResourceConfigResponse) {
	LogFunctionEntry(ctx, "resourceCertificateAuthority.ValidateConfig")

	var config KeyfactorCertificateAuthority
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	type schedulePair struct {
		name         string
		intervalPath string
		dailyPath    string
		interval     types.Int64
		daily        types.String
	}
	pairs := []schedulePair{
		{"full_scan", "full_scan_interval_minutes", "full_scan_daily_time", config.FullScanIntervalMinutes, config.FullScanDailyTime},
		{"incremental_scan", "incremental_scan_interval_minutes", "incremental_scan_daily_time", config.IncrementalScanIntervalMinutes, config.IncrementalScanDailyTime},
		{"threshold_check", "threshold_check_interval_minutes", "threshold_check_daily_time", config.ThresholdCheckIntervalMinutes, config.ThresholdCheckDailyTime},
	}
	for _, p := range pairs {
		intervalDeclared := declaredInConfig(p.interval)
		dailyDeclared := declaredInConfig(p.daily)
		if intervalDeclared && dailyDeclared {
			response.Diagnostics.AddAttributeError(
				path.Root(p.dailyPath),
				"Conflicting schedule configuration",
				fmt.Sprintf(
					"%s and %s are mutually exclusive representations of the %s schedule; declare at most one of them.",
					p.intervalPath, p.dailyPath, p.name,
				),
			)
		}
		if dailyDeclared && !p.daily.Unknown {
			parsed, err := time.Parse(caDailyTimeLayout, p.daily.Value)
			if err != nil {
				response.Diagnostics.AddAttributeError(
					path.Root(p.dailyPath),
					"Invalid daily schedule time",
					fmt.Sprintf("%s must be a UTC time-of-day formatted \"HH:MM:SS\" (e.g. \"07:00:00\"); got %q: %s", p.dailyPath, p.daily.Value, err.Error()),
				)
			} else if canonical := parsed.Format(caDailyTimeLayout); canonical != p.daily.Value {
				// time.Parse("15:04:05", ...) is lenient on field width (e.g.
				// "7:00:00" parses fine), but Command's GET always echoes the
				// zero-padded canonical spelling ("07:00:00") -- see
				// scheduleToState's use of Format(caDailyTimeLayout). A
				// non-canonical spelling therefore plans and applies
				// successfully but guarantees a "Provider produced
				// inconsistent result after apply" on every single apply
				// (planned "7:00:00" vs. applied "07:00:00"), since nothing
				// preserves the user's original spelling the way
				// preserveKeyRetentionRepresentation does for key_retention.
				// Rejecting the non-canonical spelling here, before plan/apply
				// ever runs, is simpler and more honest than trying to
				// preserve an arbitrary user spelling server-side. See
				// full-review round 2 finding #2.
				response.Diagnostics.AddAttributeError(
					path.Root(p.dailyPath),
					"Non-canonical daily schedule time",
					fmt.Sprintf(
						"%s must be zero-padded \"HH:MM:SS\"; got %q, which Command's API will echo back as %q on every "+
							"read, permanently disagreeing with the configured value. Use %q instead.",
						p.dailyPath, p.daily.Value, canonical, canonical,
					),
				)
			}
		}
	}

	response.Diagnostics.Append(validateCAConfigConstraints(config)...)

	LogFunctionExit(ctx, "resourceCertificateAuthority.ValidateConfig")
}

// caHTTPSType is the ca_type value (per this resource's "ca_type" attribute
// description: "0 = DCOM (Microsoft ADCS) or 1 = HTTPS (e.g. EJBCA)")
// identifying an HTTPS CA, the variant for which
// new_end_entity_on_renew_and_reissue=true is required.
const caHTTPSType = 1

// validateCAConfigConstraints enforces config-time constraints documented on
// this resource's attributes (F3/F4 from the Optional+Computed audit) that
// were previously only descriptive text, never actually checked:
//
//  1. enforce_unique_dn and new_end_entity_on_renew_and_reissue are mutually
//     exclusive -- rejecting both explicitly set true.
//  2. new_end_entity_on_renew_and_reissue is required to be true for HTTPS
//     CAs (ca_type=1) -- rejecting an explicit false paired with ca_type=1.
//  3. allowed_enrollment_types, use_allowed_requesters, and
//     allowed_requesters all apply to standalone CAs only -- rejecting any
//     of them being declared while standalone is explicitly set false.
//  4. auth_certificate and client_id/token_url (client-certificate vs OAuth
//     authentication) are mutually exclusive -- rejecting both declared
//     with a genuinely non-empty value at once (full-review round 1
//     finding #4).
//
// Every check here follows the same declaredInConfig-style discipline as the
// schedule validation above: a null or unknown value is never an error,
// since config-time validation cannot resolve a value that isn't known yet
// (e.g. standalone referencing another resource's not-yet-known output), and
// ValidateConfig only ever sees Config, never Plan/State. Only an explicitly
// configured, known violation is rejected. Factored out of ValidateConfig so
// it can be unit tested directly against a KeyfactorCertificateAuthority
// value.
func validateCAConfigConstraints(cfg KeyfactorCertificateAuthority) diag.Diagnostics {
	var diags diag.Diagnostics

	enforceUniqueDNKnown := !cfg.EnforceUniqueDN.Null && !cfg.EnforceUniqueDN.Unknown
	newEndEntityKnown := !cfg.NewEndEntityOnRenewAndReissue.Null && !cfg.NewEndEntityOnRenewAndReissue.Unknown

	// F3: enforce_unique_dn and new_end_entity_on_renew_and_reissue are
	// mutually exclusive -- only an issue when BOTH are explicitly true.
	if enforceUniqueDNKnown && newEndEntityKnown &&
		cfg.EnforceUniqueDN.Value && cfg.NewEndEntityOnRenewAndReissue.Value {
		diags.AddAttributeError(
			path.Root("new_end_entity_on_renew_and_reissue"),
			"Conflicting certificate authority attributes",
			"enforce_unique_dn and new_end_entity_on_renew_and_reissue are mutually exclusive and cannot both be set to true.",
		)
	}

	// F4: new_end_entity_on_renew_and_reissue is required to be true for
	// HTTPS CAs (ca_type=1) -- only an issue when ca_type is known to be 1
	// AND new_end_entity_on_renew_and_reissue is explicitly declared false;
	// leaving it undeclared/unknown is not an error here (Create/Update may
	// still default or reject it server-side).
	caTypeKnown := !cfg.CAType.Null && !cfg.CAType.Unknown
	if caTypeKnown && cfg.CAType.Value == caHTTPSType &&
		newEndEntityKnown && !cfg.NewEndEntityOnRenewAndReissue.Value {
		diags.AddAttributeError(
			path.Root("new_end_entity_on_renew_and_reissue"),
			"Invalid certificate authority attribute for HTTPS CA",
			"new_end_entity_on_renew_and_reissue must be true (or left unset) for HTTPS CAs (ca_type=1); got false.",
		)
	}

	// Auth variant mutual exclusion (full-review round 1 finding #4): Command
	// rejects a CA request that configures both OAuth (client_id/token_url)
	// and client-certificate (auth_certificate) authentication at once
	// ("Fields for OAuth and Client Certificate Authentication cannot both
	// be provided for the same CA"). Before this check, clearAuthVariant
	// (see its doc comment; case order there prefers client-certificate auth)
	// silently stripped the user's declared OAuth fields from the request
	// without telling anyone, so Command never saw -- and never reported --
	// the conflict: the CA was created/updated with only client-certificate
	// auth, and the framework then rejected the resulting apply with a
	// confusing "Provider produced inconsistent result after apply:
	// .client_id" instead of an actionable plan-time error naming the real
	// problem. Mirrors clearAuthVariant's own isKnownNonEmptyString
	// declaredness check so this rejects exactly the configs that function
	// would otherwise silently resolve. A null/unknown value on either side
	// is never an error, same discipline as every other check here.
	if isKnownNonEmptyString(cfg.AuthCertificate) &&
		(isKnownNonEmptyString(cfg.ClientID) || isKnownNonEmptyString(cfg.TokenURL)) {
		diags.AddAttributeError(
			path.Root("client_id"),
			"Conflicting certificate authority authentication configuration",
			"auth_certificate and client_id/token_url are mutually exclusive representations of certificate authority authentication; declare at most one variant. Command rejects a request that configures both OAuth and client-certificate authentication for the same CA.",
		)
	}

	// F4: allowed_enrollment_types, use_allowed_requesters, and
	// allowed_requesters all apply to standalone CAs only -- only an issue
	// when standalone is explicitly declared false; standalone left
	// undeclared/unknown never trips this (config-time validation can't
	// resolve a computed/unresolved standalone value).
	//
	// Full-review round 1 finding #6: this originally rejected on mere
	// DECLAREDNESS (any known value, including an explicit no-op like
	// allowed_enrollment_types=0, use_allowed_requesters=false, or
	// allowed_requesters=[]), rather than on a genuinely conflicting value.
	// buildCARequest has always sent these via setBoolIfKnown/equivalent
	// regardless of standalone, and Command accepts an explicit no-op
	// value on a non-standalone CA as exactly that -- a no-op (confirmed
	// live: terraform/certificate_authority_demo's committed tfstate shows
	// Command returning standalone=false with allowed_enrollment_types=3 and
	// use_allowed_requesters=false on a real non-standalone HTTPS CA). Since
	// every one of these three attributes is Optional+Computed, the
	// project's own documented import-then-codify workflow ("terraform state
	// show" output copied into config, or make lab-import's drift-check
	// step) routinely produces exactly this declared-but-no-op shape, and
	// rejecting it at plan time is a backward-compatibility break with no
	// deprecation path: existing configs that applied cleanly on prior
	// provider versions would hard-fail every plan after upgrading. Only
	// reject a value that actually conflicts with a non-standalone CA:
	// allowed_enrollment_types != 0, use_allowed_requesters == true, or a
	// non-empty allowed_requesters list.
	standaloneKnown := !cfg.Standalone.Null && !cfg.Standalone.Unknown
	if standaloneKnown && !cfg.Standalone.Value {
		if !cfg.AllowedEnrollmentTypes.Null && !cfg.AllowedEnrollmentTypes.Unknown && cfg.AllowedEnrollmentTypes.Value != 0 {
			diags.AddAttributeError(
				path.Root("allowed_enrollment_types"),
				"Invalid certificate authority attribute for a non-standalone CA",
				"allowed_enrollment_types requires standalone=true.",
			)
		}
		if !cfg.UseAllowedRequesters.Null && !cfg.UseAllowedRequesters.Unknown && cfg.UseAllowedRequesters.Value {
			diags.AddAttributeError(
				path.Root("use_allowed_requesters"),
				"Invalid certificate authority attribute for a non-standalone CA",
				"use_allowed_requesters applies to standalone CAs only.",
			)
		}
		if !cfg.AllowedRequesters.Null && !cfg.AllowedRequesters.Unknown && len(cfg.AllowedRequesters.Elems) > 0 {
			diags.AddAttributeError(
				path.Root("allowed_requesters"),
				"Invalid certificate authority attribute for a non-standalone CA",
				"allowed_requesters applies to standalone CAs only.",
			)
		}
	}

	return diags
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

	createReq, buildDiags := buildCARequest(ctx, plan)
	response.Diagnostics.Append(buildDiags...)
	if response.Diagnostics.HasError() {
		return
	}

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi
	createAPIReq := caAPI.NewCreateCertificateAuthorityRequest(ctx).CertificateAuthoritiesCertificateAuthorityRequest(createReq)
	if !plan.ForceSave.Null && !plan.ForceSave.Unknown && plan.ForceSave.Value {
		createAPIReq = createAPIReq.ForceSave(true)
	}
	resp, httpResp, err := createAPIReq.Execute()
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
	preserveKeyRetentionRepresentation(&state, plan)

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
	preserveKeyRetentionRepresentation(&newState, state)

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

	var config KeyfactorCertificateAuthority
	diags = request.Config.Get(ctx, &config)
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

	// Reconcile the schedule attribute pairs against config before building the
	// request -- see preserveCAUpdateFields for why plan alone (even after
	// UseStateForUnknown resolves it) is not sufficient here: an update that
	// declares neither variant of a pair must preserve whichever variant prior
	// state holds, and an update that switches variants must not resurrect the
	// sibling that UseStateForUnknown otherwise carries forward from state.
	preserveCAUpdateFields(&plan, config)

	updateReq, buildDiags := buildCARequest(ctx, plan)
	response.Diagnostics.Append(buildDiags...)
	if response.Diagnostics.HasError() {
		return
	}
	idInt32 := int32(id)
	updateReq.Id = &idInt32

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi
	updateAPIReq := caAPI.NewUpdateCertificateAuthorityRequest(ctx).CertificateAuthoritiesCertificateAuthorityRequest(updateReq)
	if !plan.ForceSave.Null && !plan.ForceSave.Unknown && plan.ForceSave.Value {
		updateAPIReq = updateAPIReq.ForceSave(true)
	}
	resp, httpResp, err := updateAPIReq.Execute()
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
	preserveKeyRetentionRepresentation(&newState, plan)

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
	deleteReq := caAPI.NewDeleteCertificateAuthorityByIdRequest(ctx, int32(id))
	httpResp, err := deleteReq.Execute()
	if err != nil {
		body := readHTTPResponseBody(httpResp)
		// If the CA has Windows Task Scheduler entries associated with it (DCOM
		// CAs only), clear the scan schedules via a ForceSave PUT and then retry
		// the delete.  We check for "periodic task" / "task scheduler" in the
		// body rather than the raw error code 0xA0110029, because that same code
		// is also returned on EJBCA (HTTPS) labs when the CA has associated
		// certificates — a completely different condition that must NOT trigger
		// the clear-schedule path (which would corrupt the CA record).
		isTaskSchedulerError := strings.Contains(strings.ToLower(body), "periodic task") ||
			strings.Contains(strings.ToLower(body), "task scheduler")
		if isTaskSchedulerError {
			tflog.Info(ctx, fmt.Sprintf("CA %d has periodic tasks; clearing scan schedules before delete", id))
			clearState := state
			clearState.FullScanIntervalMinutes = types.Int64{Null: true}
			clearState.FullScanDailyTime = types.String{Null: true}
			clearState.IncrementalScanIntervalMinutes = types.Int64{Null: true}
			clearState.IncrementalScanDailyTime = types.String{Null: true}
			clearState.ThresholdCheckIntervalMinutes = types.Int64{Null: true}
			clearState.ThresholdCheckDailyTime = types.String{Null: true}
			clearReq, clearBuildDiags := buildCARequest(ctx, clearState)
			response.Diagnostics.Append(clearBuildDiags...)
			if response.Diagnostics.HasError() {
				return
			}
			idInt32 := int32(id)
			clearReq.Id = &idInt32
			updateAPIReq := caAPI.NewUpdateCertificateAuthorityRequest(ctx).
				CertificateAuthoritiesCertificateAuthorityRequest(clearReq).
				ForceSave(true)
			_, httpResp2, err2 := updateAPIReq.Execute()
			if err2 != nil {
				body2 := readHTTPResponseBody(httpResp2)
				response.Diagnostics.AddError(
					"Error clearing CA scan schedules before delete.",
					fmt.Sprintf("Could not clear scan schedules for CA %d: %s. Details: %s", id, err2.Error(), body2),
				)
				return
			}
			// Retry the delete now that schedules are cleared.
			httpResp3, err3 := caAPI.NewDeleteCertificateAuthorityByIdRequest(ctx, int32(id)).Execute()
			if err3 != nil {
				body3 := readHTTPResponseBody(httpResp3)
				// Delete still failed. Restore the original scan schedules so the CA
				// is not left in a corrupted state (no schedules) after a failed delete.
				tflog.Warn(ctx, fmt.Sprintf("CA %d delete retry failed; restoring original scan schedules", id))
				restoreReq, restoreBuildDiags := buildCARequest(ctx, state)
				if restoreBuildDiags.HasError() {
					tflog.Error(ctx, fmt.Sprintf("CA %d schedule restore request could not be built: %v", id, restoreBuildDiags))
				} else {
					restoreReq.Id = &idInt32
					restoreAPIReq := caAPI.NewUpdateCertificateAuthorityRequest(ctx).
						CertificateAuthoritiesCertificateAuthorityRequest(restoreReq).
						ForceSave(true)
					if _, _, restoreErr := restoreAPIReq.Execute(); restoreErr != nil {
						tflog.Error(ctx, fmt.Sprintf("CA %d schedule restore also failed: %s", id, restoreErr.Error()))
					}
				}
				response.Diagnostics.AddError(
					"Error deleting certificate authority.",
					fmt.Sprintf("Could not delete certificate authority %d: %s. Details: %s", id, err3.Error(), body3),
				)
				return
			}
		} else {
			response.Diagnostics.AddError(
				"Error deleting certificate authority.",
				fmt.Sprintf("Could not delete certificate authority %d: %s. Details: %s", id, err.Error(), body),
			)
			return
		}
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

// ---------------------------------------------------------------------------
// key_retention helpers: int ↔ string name conversion
// ---------------------------------------------------------------------------

var keyRetentionNameToInt = map[string]int32{
	"Disabled":        0,
	"Indefinite":      1,
	"AfterExpiration": 2,
	"FromIssuance":    3,
	"0":               0,
	"1":               1,
	"2":               2,
	"3":               3,
}

var keyRetentionIntToName = map[int32]string{
	0: "Disabled",
	1: "Indefinite",
	2: "AfterExpiration",
	3: "FromIssuance",
}

// keyRetentionIntToTfString converts a *CSSCMSCoreEnumsKeyRetentionPolicy pointer
// to its named string form. Returns null if the pointer is nil.
func keyRetentionIntToTfString(v *v1.CSSCMSCoreEnumsKeyRetentionPolicy) types.String {
	if v == nil {
		return types.String{Null: true}
	}
	if name, ok := keyRetentionIntToName[int32(*v)]; ok {
		return types.String{Value: name}
	}
	// Fallback: stringify the raw integer
	return types.String{Value: strconv.Itoa(int(*v))}
}

// preserveKeyRetentionRepresentation normalizes target.KeyRetention back to
// the representation the user configured (e.g. "2") when the server's
// response denotes the same underlying enum value but always returns the
// symbolic name (e.g. "AfterExpiration"). Command accepts either numeric
// strings or symbolic names on write but only ever returns the symbolic
// name on read, so without this the Read/Create/Update response would
// permanently disagree with a numeric-string config, producing "Provider
// produced inconsistent result after apply". This mirrors the
// certificate_authority-name normalization pattern used for the
// certificate resource's certificate_authority attribute: prefer the
// user-supplied representation whenever it denotes the same value as what
// the server returned.
func preserveKeyRetentionRepresentation(target *KeyfactorCertificateAuthority, source KeyfactorCertificateAuthority) {
	if target.KeyRetention.Null || target.KeyRetention.Unknown {
		return
	}
	if source.KeyRetention.Null || source.KeyRetention.Unknown {
		return
	}
	if target.KeyRetention.Value == source.KeyRetention.Value {
		return
	}
	targetInt, targetOk := keyRetentionNameToInt[target.KeyRetention.Value]
	sourceInt, sourceOk := keyRetentionNameToInt[source.KeyRetention.Value]
	if targetOk && sourceOk && targetInt == sourceInt {
		// Same enum value, different representation (e.g. "2" vs
		// "AfterExpiration") -- keep the user's originally configured form.
		target.KeyRetention = source.KeyRetention
	}
}

// ---------------------------------------------------------------------------
// key_retention validator
// ---------------------------------------------------------------------------

type keyRetentionValidator struct{}

func (v keyRetentionValidator) Description(_ context.Context) string {
	return "key_retention must be one of: Disabled (0), Indefinite (1), AfterExpiration (2), FromIssuance (3)"
}

func (v keyRetentionValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v keyRetentionValidator) Validate(
	_ context.Context,
	req tfsdk.ValidateAttributeRequest,
	resp *tfsdk.ValidateAttributeResponse,
) {
	if req.AttributeConfig.IsNull() || req.AttributeConfig.IsUnknown() {
		return
	}
	var val string
	if s, ok := req.AttributeConfig.(types.String); ok {
		val = s.Value
	} else {
		return
	}
	if _, ok := keyRetentionNameToInt[val]; !ok {
		resp.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Invalid key_retention value",
			fmt.Sprintf(
				"key_retention must be one of: Disabled (0), Indefinite (1), AfterExpiration (2), FromIssuance (3). Got: %q",
				val,
			),
		)
	}
}

// ---------------------------------------------------------------------------
// State upgrader: schema version 0 → 1  (key_retention int64 → string)
// ---------------------------------------------------------------------------

// keyRetentionV0State is a minimal struct for reading key_retention from v0 state.
type keyRetentionV0State struct {
	KeyRetention *float64 `json:"key_retention"`
}

func (r resourceCertificateAuthority) UpgradeState(_ context.Context) map[int64]tfsdk.ResourceStateUpgrader {
	return map[int64]tfsdk.ResourceStateUpgrader{
		0: {
			StateUpgrader: upgradeCAStateV0ToV1,
		},
	}
}

func upgradeCAStateV0ToV1(ctx context.Context, req tfsdk.UpgradeResourceStateRequest, resp *tfsdk.UpgradeResourceStateResponse) {
	if req.RawState == nil {
		resp.Diagnostics.AddError(
			"Unable to upgrade certificate authority state",
			"RawState is nil; cannot proceed with state upgrade from version 0 to 1.",
		)
		return
	}

	rawJSON := req.RawState.JSON
	if len(rawJSON) == 0 {
		resp.Diagnostics.AddError(
			"Unable to upgrade certificate authority state",
			"RawState JSON is empty; cannot proceed with state upgrade from version 0 to 1.",
		)
		return
	}

	// Parse the full state into a generic map so we can mutate key_retention.
	var stateMap map[string]interface{}
	if err := json.Unmarshal(rawJSON, &stateMap); err != nil {
		resp.Diagnostics.AddError(
			"Unable to upgrade certificate authority state",
			fmt.Sprintf("Failed to unmarshal v0 state JSON: %s", err.Error()),
		)
		return
	}

	// Convert key_retention from number to named string.
	if raw, ok := stateMap["key_retention"]; ok && raw != nil {
		switch v := raw.(type) {
		case float64:
			if name, ok := keyRetentionIntToName[int32(v)]; ok {
				stateMap["key_retention"] = name
			} else {
				stateMap["key_retention"] = strconv.Itoa(int(v))
			}
		case string:
			// Already a string (shouldn't happen in v0, but be defensive)
			if intVal, ok := keyRetentionNameToInt[v]; ok {
				stateMap["key_retention"] = keyRetentionIntToName[intVal]
			}
		}
	}

	upgradedJSON, err := json.Marshal(stateMap)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to upgrade certificate authority state",
			fmt.Sprintf("Failed to marshal upgraded state JSON: %s", err.Error()),
		)
		return
	}

	// Read the upgraded JSON back into the current schema's state model.
	var newState KeyfactorCertificateAuthority
	if err := json.Unmarshal(upgradedJSON, &newState); err != nil {
		resp.Diagnostics.AddError(
			"Unable to upgrade certificate authority state",
			fmt.Sprintf("Failed to unmarshal upgraded state into model: %s", err.Error()),
		)
		return
	}

	diags := resp.State.Set(ctx, &newState)
	resp.Diagnostics.Append(diags...)
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

// normalizedJSONPropertiesModifier is the plan modifier for "properties" (F1).
// properties is Optional+Computed, storing a JSON blob (Sync External
// Certificates configuration). Command's GET re-serializes the stored JSON
// through its own encoder, which is free to reorder keys or change
// whitespace relative to whatever text the practitioner wrote in config or
// whatever text is currently in state. A bare tfsdk.UseStateForUnknown()
// only suppresses the diff when config leaves properties undeclared
// (Plan Unknown); it does nothing when config DOES declare a literal JSON
// string, since the framework's raw proposed-new-state already plans that
// literal config text verbatim. If Command's stored formatting differs from
// the config text even by whitespace, every subsequent plan shows a
// permanent properties diff (and Update resends the reformatted value)
// even though the value is semantically unchanged -- this is what
// normalizePropertiesJSON (previously dead code) exists to detect.
//
// Modify runs in this order:
//  1. No prior state (Create) -- nothing to compare against; leave the plan
//     alone.
//  2. Config is Unknown (properties computed from a not-yet-known
//     expression, e.g. referencing another resource's attribute applied in
//     the same run) -- leave the plan Unknown too, mirroring
//     tfsdk.UseStateForUnknownModifier's own guard ("otherwise interpolation
//     gets messed up"). Pinning the plan to the stale prior-state value here
//     would make apply's re-plan against the now-resolved config produce a
//     different final value than what was recorded, which Terraform core
//     rejects as "Provider produced inconsistent final plan".
//  3. Plan is Unknown (properties undeclared in config, Computed-only) --
//     fall back to plain UseStateForUnknown semantics: copy state forward.
//  4. Plan and state are both known strings and, once parsed and
//     re-marshaled, are semantically equal -- keep the prior state value
//     (byte-for-byte) so the diff (and the Update PUT) disappears.
//  5. Otherwise (a genuine value change, or either side isn't a comparable
//     JSON string) -- leave the plan as computed, surfacing a real diff.
type normalizedJSONPropertiesModifier struct{}

func (m normalizedJSONPropertiesModifier) Description(_ context.Context) string {
	return "Suppresses a properties diff when the server's stored JSON differs from state only in key order/whitespace."
}

func (m normalizedJSONPropertiesModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m normalizedJSONPropertiesModifier) Modify(_ context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil || req.AttributeConfig == nil {
		return
	}
	stateVal, ok := req.AttributeState.(types.String)
	if !ok || stateVal.Unknown {
		// No usable prior state (e.g. Create) -- nothing to compare against.
		return
	}

	if req.AttributeConfig.IsUnknown() {
		// Config itself is unknown (e.g. an interpolated reference to a
		// not-yet-applied resource) -- leave the plan Unknown rather than
		// pinning it to a stale state value that apply's re-plan may not agree
		// with once the config resolves.
		return
	}

	if resp.AttributePlan.IsUnknown() {
		// Undeclared in config: plain UseStateForUnknown semantics.
		resp.AttributePlan = req.AttributeState
		return
	}

	planVal, ok := resp.AttributePlan.(types.String)
	if !ok || planVal.Null || stateVal.Null {
		return
	}

	if normalizePropertiesJSON(planVal.Value) == normalizePropertiesJSON(stateVal.Value) {
		resp.AttributePlan = req.AttributeState
	}
}
