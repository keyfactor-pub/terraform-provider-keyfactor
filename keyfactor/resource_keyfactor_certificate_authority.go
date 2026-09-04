package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
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
		Description: "Manages a Keyfactor Command Certificate Authority (CA). Secret fields (explicit_password, auth_certificate, auth_certificate_password, client_secret) are write-only: the server never returns plaintext values, so provider reads preserve configured values from state. The force_save flag bypasses the server-side connectivity test on create/update and is also write-only.",
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
				Description: "An object indicating the password information to use for authentication with explicit_user. Write-only; cannot be read back from the server. Unlike this resource's other write-only fields, this one is not preserved when omitted: removing it from config clears the stored credential on the next apply.",
			},

			// --- Auth Certificate (write-only) ---
			"auth_certificate": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "An object containing information about the client certificate used to provide authentication to the HTTPS CA. Write-only. Unlike this resource's other write-only fields, this one is not preserved when omitted: removing it from config clears the stored credential on the next apply.",
			},
			"auth_certificate_password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "An object indicating the password for the certificate to use to authenticate to the HTTPS CA. Write-only. Unlike this resource's other write-only fields, this one is not preserved when omitted: removing it from config clears the stored credential on the next apply.",
			},

			// --- Auth Certificate metadata (read-only from server) ---
			// PlanModifiers use authVariantSiblingModifier (not a bare
			// UseStateForUnknown) so switching an existing CA from
			// client-certificate auth to OAuth in one apply nulls this stale
			// metadata on the plan instead of resurrecting it from state --
			// see authVariantSiblingModifier's doc comment.
			//
			// unknownTriggerPaths also watches auth_certificate itself: when
			// the client-certificate variant is incoming (OAuth->cert switch)
			// or rotating (a new auth_certificate value on an already
			// cert-auth CA), the server computes fresh metadata that cannot
			// be predicted at plan time, so the plan must stay Unknown rather
			// than copy stale/null state.
			"auth_certificate_issued_dn": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Issued DN of the authentication certificate (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					authVariantSiblingModifier{
						triggerPaths:        caOAuthTriggerPaths,
						unknownTriggerPaths: caCertAuthTriggerPaths,
						nullValue:           types.String{Null: true},
					},
				},
			},
			"auth_certificate_issuer_dn": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Issuer DN of the authentication certificate (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					authVariantSiblingModifier{
						triggerPaths:        caOAuthTriggerPaths,
						unknownTriggerPaths: caCertAuthTriggerPaths,
						nullValue:           types.String{Null: true},
					},
				},
			},
			"auth_certificate_thumbprint": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Thumbprint of the authentication certificate (read-only).",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					authVariantSiblingModifier{
						triggerPaths:        caOAuthTriggerPaths,
						unknownTriggerPaths: caCertAuthTriggerPaths,
						nullValue:           types.String{Null: true},
					},
				},
			},

			// --- OAuth Config (HTTPS CAs only) ---
			// PlanModifiers use authVariantSiblingModifier (not a bare
			// UseStateForUnknown) so switching an existing CA from OAuth to
			// client-certificate auth in one apply nulls these stale OAuth
			// attributes on the plan instead of resurrecting them from state --
			// see authVariantSiblingModifier's doc comment.
			"token_url": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "For HTTPS CAs, a string indicating the bearer token URL of the identity provider.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					authVariantSiblingModifier{triggerPaths: caCertAuthTriggerPaths, nullValue: types.String{Null: true}},
				},
			},
			"client_id": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "For HTTPS CAs, a string specifying the client ID used to authenticate when OAuth authentication is selected.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					authVariantSiblingModifier{triggerPaths: caCertAuthTriggerPaths, nullValue: types.String{Null: true}},
				},
			},
			"client_secret": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "For HTTPS CAs, an object indicating the secret for the client used to authenticate. Write-only; cannot be read back from the server. Unlike this resource's other write-only fields, this one is not preserved when omitted: removing it from config clears the stored credential on the next apply.",
			},
			"scope": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "For HTTPS CAs, a string indicating scopes included in token requests, separated by spaces.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					authVariantSiblingModifier{triggerPaths: caCertAuthTriggerPaths, nullValue: types.String{Null: true}},
				},
			},
			"audience": {
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "For HTTPS CAs, a string specifying the audience to include in token requests to the identity provider.",
				PlanModifiers: []tfsdk.AttributePlanModifier{
					authVariantSiblingModifier{triggerPaths: caCertAuthTriggerPaths, nullValue: types.String{Null: true}},
				},
			},

			// --- Schedules (interval minutes) ---
			// Command represents each of these three schedules as one of several mutually
			// exclusive variants (Interval, Daily, Weekly, Monthly, ExactlyOnce, Immediate);
			// this provider currently models the Interval variant only.
			"full_scan_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for the full synchronization schedule of this certificate authority. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Warning: creates a Windows Task Scheduler entry for DCOM CAs that blocks CA deletion.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"incremental_scan_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for the incremental synchronization schedule of this certificate authority. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Warning: creates a Windows Task Scheduler entry for DCOM CAs that blocks CA deletion.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"threshold_check_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for the threshold monitoring check schedule on this CA. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},

			// --- Write-only control flags ---
			"force_save": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "A Boolean indicating whether to save the CA record even if the CA connectivity test fails. Useful when provisioning a CA record before the CA server is reachable. Write-only: not returned by the server; preserved from config/state after reads.",
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

	// Schedules. Command can represent each of these three schedules
	// server-side as one of several variants (Interval, Daily, Weekly,
	// Monthly, ExactlyOnce, Immediate); this provider currently models the
	// Interval variant only.
	FullScanIntervalMinutes        types.Int64 `tfsdk:"full_scan_interval_minutes"`
	IncrementalScanIntervalMinutes types.Int64 `tfsdk:"incremental_scan_interval_minutes"`
	ThresholdCheckIntervalMinutes  types.Int64 `tfsdk:"threshold_check_interval_minutes"`

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
	// KeyfactorSchedule that can be Interval-shaped (among other variants not
	// yet modeled here: Daily/Weekly/Monthly/ExactlyOnce/Immediate -- the
	// Weekly variant in particular can't be modeled until the vendored SDK
	// can deserialize it; see scheduleToState below). An unmodeled variant
	// collapses to Null here, which is indistinguishable from "no schedule
	// configured at all" -- buildCARequest would then omit the field entirely
	// on the next PUT, which Command's full-replace semantics interpret as
	// "clear this schedule."
	state.FullScanIntervalMinutes = scheduleToState(resp.FullScan)
	state.IncrementalScanIntervalMinutes = scheduleToState(resp.IncrementalScan)
	state.ThresholdCheckIntervalMinutes = scheduleToState(resp.ThresholdCheck)

	// force_save is write-only; always null from server reads.
	state.ForceSave = types.Bool{Null: true}

	return state
}

// scheduleToState converts a Command KeyfactorSchedule (as returned for FullScan,
// IncrementalScan, or ThresholdCheck) into the Terraform attribute value used to
// represent its Interval-shaped variant, *_interval_minutes.
//
// The returned value comes back Null when the schedule is nil (no schedule
// configured) or when it holds a variant this provider does not yet model
// (Daily, Weekly, Monthly, ExactlyOnce, Immediate). An unmodeled variant still
// reads as "no schedule," so an Update() that doesn't touch this attribute
// would omit it from the PUT and clear it. This is a known open gap for the
// Weekly variant specifically: the vendored SDK cannot even deserialize it
// (SystemDayOfWeek expects an int; Command returns day-name strings), so a
// fix needs to land in the SDK, not here.
func scheduleToState(sched *v1.KeyfactorCommonSchedulingKeyfactorSchedule) types.Int64 {
	if sched == nil || sched.Interval == nil {
		return types.Int64{Null: true}
	}
	return types.Int64{Value: int64(sched.Interval.GetMinutes())}
}

// buildSchedule constructs a Command KeyfactorSchedule from a plan/state
// Interval attribute value. Returns nil when the value is not known, matching
// the "omit the field from the request" semantics buildCARequest relies on
// elsewhere.
func buildSchedule(intervalMinutes types.Int64) *v1.KeyfactorCommonSchedulingKeyfactorSchedule {
	if !intervalMinutes.Null && !intervalMinutes.Unknown {
		minutes := int32(intervalMinutes.Value)
		return &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Interval: &v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes},
		}
	}
	return nil
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
	//
	// AuthCertificate/AuthCertificatePassword are typed map[string]interface{}
	// on this v25+ request model (unlike ExplicitPassword/ClientSecret, which
	// remain *CSSCMSDataModelModelsKeyfactorAPISecret) -- an OpenAPI generator
	// artifact, not a different wire shape. Build the same
	// {"SecretValue": "..."} object by hand so the request body Command
	// receives is unchanged.
	if !plan.AuthCertificate.Null && !plan.AuthCertificate.Unknown {
		req.AuthCertificate = map[string]interface{}{"SecretValue": plan.AuthCertificate.Value}
	}
	if !plan.AuthCertificatePassword.Null && !plan.AuthCertificatePassword.Unknown {
		req.AuthCertificatePassword = map[string]interface{}{"SecretValue": plan.AuthCertificatePassword.Value}
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

	// Schedules. Each of FullScan/IncrementalScan/ThresholdCheck is represented
	// as an Interval schedule. buildSchedule returns nil when the attribute is
	// null/unknown, which -- per Command's full-replace PUT semantics -- omits
	// the field from the request and clears it server-side; an update that
	// simply didn't declare the attribute relies on Optional+Computed with
	// UseStateForUnknown to carry the prior state value forward so this does
	// not happen.
	req.FullScan = buildSchedule(plan.FullScanIntervalMinutes)
	req.IncrementalScan = buildSchedule(plan.IncrementalScanIntervalMinutes)
	req.ThresholdCheck = buildSchedule(plan.ThresholdCheckIntervalMinutes)

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

// caOAuthTriggerPaths and caCertAuthTriggerPaths are the shared trigger-path
// sets for authVariantSiblingModifier, hoisted out of the schema's seven
// call sites (three cert-metadata attributes x caOAuthTriggerPaths, four
// OAuth attributes x caCertAuthTriggerPaths) so the OAuth trigger set used by
// all three cert-metadata attributes -- which must stay identical for the
// variant-switch reconciliation below to be symmetric -- cannot drift apart
// if a fifth OAuth attribute is ever added to some call sites but not
// others. caCertAuthTriggerPaths additionally serves as auth_certificate_*'s
// unknownTriggerPaths (see authVariantSiblingModifier's doc comment).
var (
	caOAuthTriggerPaths    = []path.Path{path.Root("client_id"), path.Root("token_url"), path.Root("scope"), path.Root("audience")}
	caCertAuthTriggerPaths = []path.Path{path.Root("auth_certificate")}
)

// authVariantSiblingModifier is the plan-time half of certificate-authority
// auth-variant switch reconciliation -- the OAuth<->client-certificate
// counterpart of the terraform-plugin-framework v0.10 mechanism this works
// around: a Computed attribute whose own config is null is marked Unknown at
// plan time, and a bare tfsdk.UseStateForUnknown then pins that Unknown
// straight back to the stale prior-state value with no notion that a sibling
// attribute is taking over.
//
// token_url/client_id/scope/audience (OAuth) are Optional+Computed, and
// auth_certificate_issued_dn/issuer_dn/thumbprint (client-certificate auth
// metadata) are Computed, all previously wired to only a bare
// UseStateForUnknown. Switching an existing CA between auth variants in one
// apply -- e.g. removing token_url/client_id from config and declaring
// auth_certificate instead -- pinned the OUTGOING variant's stale attributes
// onto the recorded plan, while clearAuthVariant (called from buildCARequest
// at apply time) strips those same fields from the PUT and the server's
// post-switch representation zeroes them out (empty string for OAuth fields,
// per clearAuthVariant's own doc comment; null for cert metadata, per
// caResponseToState's else-branch) -- "Provider produced inconsistent result
// after apply" on every single auth-variant switch, in both directions.
//
// This is a group relationship, not a single 1:1 sibling: an OAuth
// attribute's switch-away signal is auth_certificate alone becoming
// genuinely configured, while a cert-metadata attribute's switch-away signal
// is ANY of the four OAuth attributes becoming genuinely configured -- hence
// a slice of trigger paths rather than one. "Genuinely configured" reuses
// isKnownNonEmptyString's discipline (known and non-empty), the same test
// clearAuthVariant and validateCAConfigConstraints already apply to these
// exact attributes, so schema, apply-time stripping, and config validation
// all agree on what counts as "this variant is in use."
//
// validateCAConfigConstraints's auth-variant mutual-exclusion check rejects
// any config that declares both variants at once with a genuinely non-empty
// value, so a variant-switch config only ever declares the incoming variant
// -- the "multiple triggers fire for the same attribute" case is therefore
// unreachable in practice.
//
// unknownTriggerPaths fixes a second gap:
// the three cert-metadata attributes' triggerPaths only cover the OUTGOING
// direction (an OAuth attribute becoming declared means client-certificate
// auth is going away, so nulling is correct). They have no trigger at all
// for the INCOMING/rotating direction -- auth_certificate itself becoming
// declared -- so on an OAuth->cert-auth switch, or on rotating
// auth_certificate on an already cert-auth CA, none of triggerPaths fire and
// the tail resurrects the stale (null, for a switch; old, for a rotation)
// prior-state metadata onto the plan, while the PUT response carries the
// server's freshly computed DN/thumbprint for the new certificate --
// "Provider produced inconsistent result after apply" on the very switch
// case fixed for the OAuth attributes above, and on every cert rotation.
//
// A trigger path in unknownTriggerPaths behaves differently from one in
// triggerPaths: instead of nulling the plan, it leaves the plan Unknown
// (the server will compute a value neither state nor config can predict) --
// but only when the trigger's config value actually differs from its own
// prior state value. auth_certificate is Optional but not Computed
// (write-only, never preserved from state by the framework), so a
// steady-state cert-auth CA must re-declare the identical certificate value
// in config on every single apply just to avoid clearAuthVariant treating it
// as cleared; comparing config against state (not merely checking
// "declared") is what distinguishes that steady-state redeclaration --
// which must fall through to ordinary UseStateForUnknown carry-forward, or
// every apply would show a perpetual "(known after apply)" diff on metadata
// that never actually changed -- from a genuine incoming switch or rotation.
type authVariantSiblingModifier struct {
	// triggerPaths: when any is genuinely declared (known, non-empty) in
	// config, the OTHER variant is taking over -- null this attribute's plan
	// instead of resurrecting its stale prior-state value.
	triggerPaths []path.Path

	// unknownTriggerPaths: when any is genuinely declared in config AND its
	// value differs from its own prior state value, the variant THIS
	// attribute is metadata for is incoming or rotating this apply -- leave
	// the plan Unknown so the server-computed value isn't pinned stale (nor
	// incorrectly nulled). An unchanged, steadily-redeclared trigger value
	// falls through to ordinary UseStateForUnknown carry-forward instead.
	unknownTriggerPaths []path.Path

	nullValue attr.Value
}

func (m authVariantSiblingModifier) Description(_ context.Context) string {
	return "Uses the prior state value unless the other certificate authority auth variant is declared in config, in which case the plan is nulled so the new variant can take over cleanly."
}

func (m authVariantSiblingModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m authVariantSiblingModifier) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil || req.AttributeConfig == nil {
		return
	}
	if !resp.AttributePlan.IsUnknown() {
		return
	}
	if req.AttributeConfig.IsUnknown() {
		return
	}

	anyUnknown := false
	for _, triggerPath := range m.triggerPaths {
		var triggerConfig types.String
		if diags := req.Config.GetAttribute(ctx, triggerPath, &triggerConfig); diags.HasError() {
			// Conservative fallback: treat this trigger as undeclared rather
			// than erroring the plan over a diagnostic lookup failure.
			continue
		}
		if triggerConfig.Unknown {
			anyUnknown = true
			continue
		}
		if isKnownNonEmptyString(triggerConfig) {
			// The other auth variant is genuinely declared in config and
			// taking over this apply -- do not resurrect this attribute's
			// stale prior-state value onto the plan.
			resp.AttributePlan = m.nullValue
			return
		}
	}

	for _, triggerPath := range m.unknownTriggerPaths {
		var triggerConfig types.String
		if diags := req.Config.GetAttribute(ctx, triggerPath, &triggerConfig); diags.HasError() {
			continue
		}
		if triggerConfig.Unknown {
			anyUnknown = true
			continue
		}
		if !isKnownNonEmptyString(triggerConfig) {
			continue
		}
		// The variant this attribute is metadata for is genuinely declared
		// in config. Only treat it as incoming/rotating -- and therefore
		// leave the plan Unknown for the server to compute a fresh value --
		// if the trigger's config value actually differs from its own prior
		// state value; an unchanged, steadily-redeclared value (the normal
		// shape of every apply for a write-only, non-Computed field like
		// auth_certificate) falls through to ordinary UseStateForUnknown
		// carry-forward below instead, so a steady-state CA doesn't show a
		// perpetual diff on its metadata attributes.
		var triggerState types.String
		if diags := req.State.GetAttribute(ctx, triggerPath, &triggerState); diags.HasError() {
			// Conservative: can't tell whether it changed, so assume it did
			// rather than risk resurrecting stale metadata onto the plan.
			return
		}
		if triggerState.Null || triggerState.Unknown || triggerState.Value != triggerConfig.Value {
			return
		}
	}

	if anyUnknown {
		// At least one trigger attribute depends on some other not-yet-known
		// value this apply -- cannot yet tell whether the other variant is
		// taking over. Be conservative and leave this attribute Unknown too,
		// deferring the decision to apply time rather than guessing.
		return
	}

	// No trigger declared (or an unknownTriggerPaths trigger declared but
	// unchanged from state): ordinary UseStateForUnknown semantics. Mirrors
	// tfsdk.UseStateForUnknownModifier's own IsNull guard.
	if req.AttributeState.IsNull() || req.AttributeState.IsUnknown() {
		return
	}
	resp.AttributePlan = req.AttributeState
}

// ValidateConfig rejects config-time constraint violations before plan/apply
// ever runs -- see validateCAConfigConstraints for the checks performed.
func (r resourceCertificateAuthority) ValidateConfig(ctx context.Context, request tfsdk.ValidateResourceConfigRequest, response *tfsdk.ValidateResourceConfigResponse) {
	LogFunctionEntry(ctx, "resourceCertificateAuthority.ValidateConfig")

	var config KeyfactorCertificateAuthority
	diags := request.Config.Get(ctx, &config)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
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
// this resource's attributes that were previously only descriptive text,
// never actually checked:
//
//  1. enforce_unique_dn and new_end_entity_on_renew_and_reissue are mutually
//     exclusive -- rejecting both explicitly set true.
//  2. new_end_entity_on_renew_and_reissue is required to be true for HTTPS
//     CAs (ca_type=1) -- rejecting an explicit false paired with ca_type=1.
//  3. auth_certificate and client_id/token_url (client-certificate vs OAuth
//     authentication) are mutually exclusive -- rejecting both declared
//     with a genuinely non-empty value at once.
//
// A fourth check -- rejecting allowed_enrollment_types/use_allowed_requesters/
// allowed_requesters declared alongside standalone=false, on the theory that
// those three attributes are standalone-only -- was tried and then REMOVED.
// See that check's own removed doc comment, preserved in git history, for the full
// backward-compatibility failure it caused; the short version: Command's own
// resting/echoed value for allowed_enrollment_types on a real non-standalone
// HTTPS CA is 3, not 0 (confirmed against a live lab CA and this repo's own
// committed certificate_authority_demo tfstate), so rejecting any non-zero
// value there was rejecting the server's own default -- a hard break for
// every config produced by this project's own documented import-then-codify
// workflow. use_allowed_requesters/allowed_requesters are removed alongside
// it for consistency: Command's API docs describe all three attributes with
// identical wording ("supported only for standalone CAs"), which further
// investigation showed does NOT mean "rejected/forced to zero for
// non-standalone" for allowed_enrollment_types -- and this provider has no
// live evidence (no standalone CA exists in the available lab to compare
// against) that Command enforces anything stricter for the other two. Absent
// proof the server actually rejects a non-standalone CA holding
// use_allowed_requesters=true or a non-empty allowed_requesters, this
// provider now relies on Command's own server-side validation for all three
// rather than guessing at a client-side constraint that already proved wrong
// once for the sibling attribute sharing the identical doc language.
//
// Every check here follows the same discipline: a null or unknown value is
// never an error, since config-time validation cannot resolve a value that
// isn't known yet (e.g. standalone referencing another resource's not-yet-known
// output), and
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

	// Auth variant mutual exclusion: Command
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

	// No standalone-only constraint on allowed_enrollment_types/
	// use_allowed_requesters/allowed_requesters is enforced here -- see this
	// function's doc comment for why the check that
	// used to live here was removed rather than merely relaxed further.

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

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid certificate authority ID.",
			fmt.Sprintf("Could not parse certificate authority ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Updating certificate authority ID %d", id))

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
		// certificates : a completely different condition that must NOT trigger
		// the clear-schedule path (which would corrupt the CA record).
		isTaskSchedulerError := strings.Contains(strings.ToLower(body), "periodic task") ||
			strings.Contains(strings.ToLower(body), "task scheduler")
		if isTaskSchedulerError {
			tflog.Info(ctx, fmt.Sprintf("CA %d has periodic tasks; clearing scan schedules before delete", id))
			clearState := state
			clearState.FullScanIntervalMinutes = types.Int64{Null: true}
			clearState.IncrementalScanIntervalMinutes = types.Int64{Null: true}
			clearState.ThresholdCheckIntervalMinutes = types.Int64{Null: true}
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
