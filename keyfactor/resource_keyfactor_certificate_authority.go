package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
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
				Type:     types.ListType{ElemType: types.StringType},
				Optional: true,
				Computed: true,
				Description: "An array of strings indicating Keyfactor Command security roles that are allowed to enroll for certificates via Keyfactor Command for this CA. Applies to standalone CAs only. " +
					"Requires Keyfactor Command v25.5 or later for reads to reflect the server's actual list; on older Command versions this may read back empty even when configured server-side. " +
					"Omit to leave unmanaged (preserved on update); set [] explicitly to clear.",
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

			// --- Schedules (flat interval minutes, daily time-of-day, or weekly days+time) ---
			// Command represents each of these three schedules as one of several mutually
			// exclusive variants (Interval, Daily, Weekly, Monthly, ExactlyOnce, Immediate);
			// this provider models the three variants seen in practice: Interval, Daily, and
			// Weekly. Declaring attributes from more than one of these variants for the same
			// schedule is invalid and rejected at plan time (ValidateConfig). Weekly is
			// represented by a CO-REQUIRED pair (*_weekly_days, *_weekly_time): declaring one
			// without the other is also rejected at plan time.
			//
			// Every schedule attribute uses pairedWith(...siblings) instead of a bare
			// tfsdk.UseStateForUnknown(): a plain UseStateForUnknown resurrects this
			// attribute's PRIOR STATE value as Known on every plan, even when the config
			// just switched the schedule to a different variant -- so an Interval->Daily
			// switch would plan the OLD interval as still Known alongside the new daily
			// time, and Update would then send both (or send the stale interval alone if
			// buildSchedule's precedence silently dropped the daily value), producing a
			// PUT that doesn't match what the user declared and, after the server echoes
			// it back on the following Read, "Provider produced inconsistent result after
			// apply" (F182-1). pairedWith instead plans this attribute explicitly Null the
			// moment any OTHER variant in the group is declared in config, so the diff
			// Terraform shows (e.g. full_scan_interval_minutes: 60 -> null) is truthful.
			// Each attribute's sibling list names every OTHER variant's attribute(s), never
			// its own co-attribute (e.g. full_scan_weekly_days does not list
			// full_scan_weekly_time as a sibling -- the two are co-required, not mutually
			// exclusive, with each other).
			"full_scan_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for the full synchronization schedule of this certificate authority. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Mutually exclusive with full_scan_daily_time and full_scan_weekly_days/full_scan_weekly_time. Warning: creates a Windows Task Scheduler entry for DCOM CAs that blocks CA deletion. Omit to leave the server-side schedule unmanaged (preserved on update); set 0 (interval), \"\" (daily), or the weekly clear sentinel ([] + \"\") explicitly to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("full_scan_daily_time", "full_scan_weekly_days", "full_scan_weekly_time")},
			},
			"full_scan_daily_time": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), that sets a once-daily full synchronization schedule for this certificate authority. Mutually exclusive with full_scan_interval_minutes and full_scan_weekly_days/full_scan_weekly_time. Omit to leave the server-side schedule unmanaged (preserved on update); set 0 (interval), \"\" (daily), or the weekly clear sentinel ([] + \"\") explicitly to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("full_scan_interval_minutes", "full_scan_weekly_days", "full_scan_weekly_time")},
			},
			"full_scan_weekly_days": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				Computed:      true,
				Description:   "Day names (e.g. [\"Monday\", \"Friday\"]) for a weekly full synchronization schedule for this certificate authority. Must be exact, case-sensitive day names: Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday. Co-required with full_scan_weekly_time (both or neither). Mutually exclusive with full_scan_interval_minutes and full_scan_daily_time. Omit to leave the server-side schedule unmanaged (preserved on update); set [] together with full_scan_weekly_time = \"\" to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("full_scan_interval_minutes", "full_scan_daily_time")},
			},
			"full_scan_weekly_time": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), for a weekly full synchronization schedule for this certificate authority. Co-required with full_scan_weekly_days (both or neither). Mutually exclusive with full_scan_interval_minutes and full_scan_daily_time. Omit to leave the server-side schedule unmanaged (preserved on update); set \"\" together with full_scan_weekly_days = [] to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("full_scan_interval_minutes", "full_scan_daily_time")},
			},
			"incremental_scan_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for the incremental synchronization schedule of this certificate authority. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Mutually exclusive with incremental_scan_daily_time and incremental_scan_weekly_days/incremental_scan_weekly_time. Warning: creates a Windows Task Scheduler entry for DCOM CAs that blocks CA deletion. Omit to leave the server-side schedule unmanaged (preserved on update); set 0 (interval), \"\" (daily), or the weekly clear sentinel ([] + \"\") explicitly to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("incremental_scan_daily_time", "incremental_scan_weekly_days", "incremental_scan_weekly_time")},
			},
			"incremental_scan_daily_time": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), that sets a once-daily incremental synchronization schedule for this certificate authority. Mutually exclusive with incremental_scan_interval_minutes and incremental_scan_weekly_days/incremental_scan_weekly_time. Omit to leave the server-side schedule unmanaged (preserved on update); set 0 (interval), \"\" (daily), or the weekly clear sentinel ([] + \"\") explicitly to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("incremental_scan_interval_minutes", "incremental_scan_weekly_days", "incremental_scan_weekly_time")},
			},
			"incremental_scan_weekly_days": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				Computed:      true,
				Description:   "Day names (e.g. [\"Monday\", \"Friday\"]) for a weekly incremental synchronization schedule for this certificate authority. Must be exact, case-sensitive day names: Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday. Co-required with incremental_scan_weekly_time (both or neither). Mutually exclusive with incremental_scan_interval_minutes and incremental_scan_daily_time. Omit to leave the server-side schedule unmanaged (preserved on update); set [] together with incremental_scan_weekly_time = \"\" to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("incremental_scan_interval_minutes", "incremental_scan_daily_time")},
			},
			"incremental_scan_weekly_time": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), for a weekly incremental synchronization schedule for this certificate authority. Co-required with incremental_scan_weekly_days (both or neither). Mutually exclusive with incremental_scan_interval_minutes and incremental_scan_daily_time. Omit to leave the server-side schedule unmanaged (preserved on update); set \"\" together with incremental_scan_weekly_days = [] to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("incremental_scan_interval_minutes", "incremental_scan_daily_time")},
			},
			"threshold_check_interval_minutes": {
				Type:          types.Int64Type,
				Optional:      true,
				Computed:      true,
				Description:   "Interval in minutes for the threshold monitoring check schedule on this CA. Must be one of: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720. Mutually exclusive with threshold_check_daily_time and threshold_check_weekly_days/threshold_check_weekly_time. Omit to leave the server-side schedule unmanaged (preserved on update); set 0 (interval), \"\" (daily), or the weekly clear sentinel ([] + \"\") explicitly to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("threshold_check_daily_time", "threshold_check_weekly_days", "threshold_check_weekly_time")},
			},
			"threshold_check_daily_time": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), that sets a once-daily threshold monitoring check schedule on this CA. Mutually exclusive with threshold_check_interval_minutes and threshold_check_weekly_days/threshold_check_weekly_time. Omit to leave the server-side schedule unmanaged (preserved on update); set 0 (interval), \"\" (daily), or the weekly clear sentinel ([] + \"\") explicitly to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("threshold_check_interval_minutes", "threshold_check_weekly_days", "threshold_check_weekly_time")},
			},
			"threshold_check_weekly_days": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				Computed:      true,
				Description:   "Day names (e.g. [\"Monday\", \"Friday\"]) for a weekly threshold monitoring check schedule on this CA. Must be exact, case-sensitive day names: Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday. Co-required with threshold_check_weekly_time (both or neither). Mutually exclusive with threshold_check_interval_minutes and threshold_check_daily_time. Omit to leave the server-side schedule unmanaged (preserved on update); set [] together with threshold_check_weekly_time = \"\" to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("threshold_check_interval_minutes", "threshold_check_daily_time")},
			},
			"threshold_check_weekly_time": {
				Type:          types.StringType,
				Optional:      true,
				Computed:      true,
				Description:   "UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), for a weekly threshold monitoring check schedule on this CA. Co-required with threshold_check_weekly_days (both or neither). Mutually exclusive with threshold_check_interval_minutes and threshold_check_daily_time. Omit to leave the server-side schedule unmanaged (preserved on update); set \"\" together with threshold_check_weekly_days = [] to clear it.",
				PlanModifiers: []tfsdk.AttributePlanModifier{pairedWith("threshold_check_interval_minutes", "threshold_check_daily_time")},
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

	// Schedules
	FullScanIntervalMinutes        types.Int64  `tfsdk:"full_scan_interval_minutes"`
	FullScanDailyTime              types.String `tfsdk:"full_scan_daily_time"`
	FullScanWeeklyDays             types.List   `tfsdk:"full_scan_weekly_days"`
	FullScanWeeklyTime             types.String `tfsdk:"full_scan_weekly_time"`
	IncrementalScanIntervalMinutes types.Int64  `tfsdk:"incremental_scan_interval_minutes"`
	IncrementalScanDailyTime       types.String `tfsdk:"incremental_scan_daily_time"`
	IncrementalScanWeeklyDays      types.List   `tfsdk:"incremental_scan_weekly_days"`
	IncrementalScanWeeklyTime      types.String `tfsdk:"incremental_scan_weekly_time"`
	ThresholdCheckIntervalMinutes  types.Int64  `tfsdk:"threshold_check_interval_minutes"`
	ThresholdCheckDailyTime        types.String `tfsdk:"threshold_check_daily_time"`
	ThresholdCheckWeeklyDays       types.List   `tfsdk:"threshold_check_weekly_days"`
	ThresholdCheckWeeklyTime       types.String `tfsdk:"threshold_check_weekly_time"`

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

	// Auth certificate metadata from response. F9: a CA without an auth
	// certificate configured must read these three as Null, not the Go
	// zero-value known-empty-string a bare composite-literal omission would
	// otherwise leave them at -- matching the null-safe pattern
	// (boolPtrToTfBool/nullableStringToTfString/etc.) used for every other
	// pointer field in this function.
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
	// KeyfactorSchedule that can be Interval-shaped, Daily-shaped, OR
	// Weekly-shaped (among other variants not yet supported here). A
	// Daily-shaped or Weekly-shaped schedule must NOT collapse to Null here —
	// Null is indistinguishable from "no schedule configured at all" and
	// buildCARequest would then omit the field entirely on the next PUT, which
	// Command's full-replace semantics interpret as "clear this schedule",
	// silently wiping a real, live Daily or Weekly scan schedule server-side.
	state.FullScanIntervalMinutes, state.FullScanDailyTime, state.FullScanWeeklyDays, state.FullScanWeeklyTime = scheduleToState(resp.FullScan)
	state.IncrementalScanIntervalMinutes, state.IncrementalScanDailyTime, state.IncrementalScanWeeklyDays, state.IncrementalScanWeeklyTime = scheduleToState(resp.IncrementalScan)
	state.ThresholdCheckIntervalMinutes, state.ThresholdCheckDailyTime, state.ThresholdCheckWeeklyDays, state.ThresholdCheckWeeklyTime = scheduleToState(resp.ThresholdCheck)

	// force_save is write-only; always null from server reads.
	state.ForceSave = types.Bool{Null: true}

	return state
}

// caDailyTimeLayout is the Go reference-time layout for the *_daily_time
// attributes: a bare UTC time-of-day, "HH:MM:SS" (e.g. "07:00:00"). Command's
// GET echoes back the exact time-of-day it was given but rewrites the date
// component to the current date (confirmed live against the Command API), so
// any date/offset information in the wire format would be pure noise that
// can never round-trip -- only the time-of-day is meaningful. See F182-2.
const caDailyTimeLayout = "15:04:05"

// caDayNameToEnum maps the exact, case-sensitive day names this provider
// accepts for *_weekly_days to Command's SystemDayOfWeek enum values. Only
// this canonical capitalization is accepted (validated in
// validateCAScheduleAttributes) rather than normalizing other casings, so
// that a value round-tripped from Read (see caDayEnumToName) always compares
// equal, byte-for-byte, to what the practitioner declared — avoiding a plan
// modifier or extra normalization layer just to reconcile case differences.
var caDayNameToEnum = map[string]v1.SystemDayOfWeek{
	"Sunday":    v1.SYSTEMDAYOFWEEK_Sunday,
	"Monday":    v1.SYSTEMDAYOFWEEK_Monday,
	"Tuesday":   v1.SYSTEMDAYOFWEEK_Tuesday,
	"Wednesday": v1.SYSTEMDAYOFWEEK_Wednesday,
	"Thursday":  v1.SYSTEMDAYOFWEEK_Thursday,
	"Friday":    v1.SYSTEMDAYOFWEEK_Friday,
	"Saturday":  v1.SYSTEMDAYOFWEEK_Saturday,
}

// caDayEnumToName is the reverse of caDayNameToEnum, used by scheduleToState
// to render a server-reported Weekly schedule's Days back into the same
// canonical day-name strings *_weekly_days accepts.
var caDayEnumToName = map[v1.SystemDayOfWeek]string{
	v1.SYSTEMDAYOFWEEK_Sunday:    "Sunday",
	v1.SYSTEMDAYOFWEEK_Monday:    "Monday",
	v1.SYSTEMDAYOFWEEK_Tuesday:   "Tuesday",
	v1.SYSTEMDAYOFWEEK_Wednesday: "Wednesday",
	v1.SYSTEMDAYOFWEEK_Thursday:  "Thursday",
	v1.SYSTEMDAYOFWEEK_Friday:    "Friday",
	v1.SYSTEMDAYOFWEEK_Saturday:  "Saturday",
}

// caDayNamesToEnums converts *_weekly_days config values (day names) into the
// SystemDayOfWeek enum values buildSchedule needs to construct a Weekly wire
// request. Returns an error naming the offending value if any name is not
// one of the seven canonical, case-sensitive day names.
func caDayNamesToEnums(names []string) ([]v1.SystemDayOfWeek, error) {
	days := make([]v1.SystemDayOfWeek, 0, len(names))
	for _, n := range names {
		d, ok := caDayNameToEnum[n]
		if !ok {
			return nil, fmt.Errorf("invalid weekly day name %q: must be one of Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday (exact, case-sensitive)", n)
		}
		days = append(days, d)
	}
	return days, nil
}

// caDayEnumsToNames converts a server-reported Weekly schedule's Days into
// the canonical day-name strings *_weekly_days stores in state, sorted by
// enum value (Sunday=0 .. Saturday=6) for a stable, deterministic ordering
// regardless of what order Command returned them in -- without this, a
// server-side reorder of the same day set (no real change) would show as
// spurious drift on every plan.
func caDayEnumsToNames(days []v1.SystemDayOfWeek) []string {
	sorted := make([]v1.SystemDayOfWeek, len(days))
	copy(sorted, days)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	names := make([]string, 0, len(sorted))
	for _, d := range sorted {
		if name, ok := caDayEnumToName[d]; ok {
			names = append(names, name)
		}
	}
	return names
}

// scheduleToState converts a Command KeyfactorSchedule (as returned for FullScan,
// IncrementalScan, or ThresholdCheck) into the set of Terraform attribute values used
// to represent it: an Interval-shaped *_interval_minutes value, a Daily-shaped
// *_daily_time value, and a Weekly-shaped *_weekly_days/*_weekly_time pair. Command's
// schedule is a tagged union — at most one variant is populated at a time — so at most
// one of the three representations returned will be non-null (the Weekly pair counts
// as a single representation: both its values are set together, or neither is).
// All four come back Null when the schedule is nil (server has no schedule configured)
// or when it holds a variant this provider does not yet model (Monthly/ExactlyOnce/
// Immediate); in the latter case, Update's read-modify-write preserves whatever the
// server returned verbatim (see the GET-before-PUT block in Update), since this
// function has no attribute pair to represent those variants in state.
func scheduleToState(sched *v1.KeyfactorCommonSchedulingKeyfactorSchedule) (types.Int64, types.String, types.List, types.String) {
	interval := types.Int64{Null: true}
	daily := types.String{Null: true}
	weeklyDays := types.List{Null: true, ElemType: types.StringType}
	weeklyTime := types.String{Null: true}
	if sched == nil {
		return interval, daily, weeklyDays, weeklyTime
	}
	if sched.Interval != nil {
		interval = types.Int64{Value: int64(sched.Interval.GetMinutes())}
	}
	if sched.Daily != nil && sched.Daily.Time != nil {
		daily = types.String{Value: sched.Daily.Time.UTC().Format(caDailyTimeLayout)}
	}
	if sched.Weekly != nil {
		weeklyDays = stringSliceToTfList(caDayEnumsToNames(sched.Weekly.Days))
		if sched.Weekly.Time != nil {
			weeklyTime = types.String{Value: sched.Weekly.Time.UTC().Format(caDailyTimeLayout)}
		} else {
			weeklyTime = types.String{Value: ""}
		}
	}
	return interval, daily, weeklyDays, weeklyTime
}

// buildSchedule constructs a Command KeyfactorSchedule from a plan/state's Interval,
// Daily, and Weekly attribute values. The three representations are mutually
// exclusive -- primarily enforced at plan time by
// resourceCertificateAuthority.ValidateConfig, which sees Config, not Plan. As
// defense-in-depth against a case ValidateConfig cannot observe (e.g. Unknown Config
// references that all happen to resolve to Known, non-sentinel values by apply time),
// buildSchedule itself also rejects the case where more than one variant is Known and
// non-sentinel, rather than silently letting one variant take precedence and
// discarding the others. The Weekly pair (weeklyDays/weeklyTime) is co-required --
// declaring exactly one of the two is also rejected here as defense-in-depth, mirroring
// validateCAScheduleAttributes's plan-time check.
//
// G2: intervalMinutes == 0, dailyTime == "", and the weekly pair (weeklyDays == []
// AND weeklyTime == "") are declarative CLEAR sentinels, not real schedule values --
// any one of them, Known but at its sentinel value, contributes nothing to the built
// schedule (same as if it were Null), so the schedule returns nil here just like a
// fully-undeclared set. The difference between a sentinel and undeclared only matters
// one layer up, at declaredInConfig(): a sentinel IS declared, so
// preserveCAUpdateFields/applyUndeclaredScheduleFallback must NOT treat it as
// "undeclared, preserve/fall back to the current value" -- this is what turns the nil
// this function returns into an actual clearing PUT (field omitted) rather than the
// fallback re-populating it right back.
//
// Returns (nil, nil) when none of the three variants is set (or only a sentinel is
// set), matching the "omit the field" semantics buildCARequest relies on elsewhere.
// dailyTime/weeklyTime are parsed as a bare UTC time-of-day (caDailyTimeLayout) and
// anchored to a fixed, arbitrary date -- Command rewrites the date component to the
// current date server-side regardless of what is sent (confirmed live for Daily; the
// same anchoring is applied to Weekly for consistency), so a fixed anchor keeps this
// function deterministic without affecting the schedule that is actually applied.
func buildSchedule(ctx context.Context, intervalMinutes types.Int64, dailyTime types.String, weeklyDays types.List, weeklyTime types.String) (*v1.KeyfactorCommonSchedulingKeyfactorSchedule, error) {
	intervalKnown := !intervalMinutes.Null && !intervalMinutes.Unknown
	dailyKnown := !dailyTime.Null && !dailyTime.Unknown
	weeklyDaysKnown := !weeklyDays.Null && !weeklyDays.Unknown
	weeklyTimeKnown := !weeklyTime.Null && !weeklyTime.Unknown

	if weeklyDaysKnown != weeklyTimeKnown {
		return nil, fmt.Errorf("weekly_days and weekly_time are co-required; set both or neither")
	}
	weeklyKnown := weeklyDaysKnown && weeklyTimeKnown

	variantsDeclared := 0
	if intervalKnown {
		variantsDeclared++
	}
	if dailyKnown {
		variantsDeclared++
	}
	if weeklyKnown {
		variantsDeclared++
	}
	if variantsDeclared > 1 {
		return nil, fmt.Errorf("interval, daily time, and weekly schedule are mutually exclusive; set at most one")
	}

	if intervalKnown && intervalMinutes.Value != 0 {
		minutes := int32(intervalMinutes.Value)
		return &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Interval: &v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes},
		}, nil
	}
	if dailyKnown && dailyTime.Value != "" {
		t, err := time.Parse(caDailyTimeLayout, dailyTime.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid daily time %q: %w", dailyTime.Value, err)
		}
		anchored := time.Date(2000, 1, 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		return &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Daily: &v1.KeyfactorCommonSchedulingModelsTimeModel{Time: &anchored},
		}, nil
	}
	if weeklyKnown {
		var dayNames []string
		weeklyDays.ElementsAs(ctx, &dayNames, false)
		daysEmpty := len(dayNames) == 0
		timeEmpty := weeklyTime.Value == ""
		if daysEmpty != timeEmpty {
			return nil, fmt.Errorf("weekly_days and weekly_time must either both be set to real values or both be empty (to clear the schedule); got a mismatched pair")
		}
		if !daysEmpty && !timeEmpty {
			days, err := caDayNamesToEnums(dayNames)
			if err != nil {
				return nil, err
			}
			t, err := time.Parse(caDailyTimeLayout, weeklyTime.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid weekly time %q: %w", weeklyTime.Value, err)
			}
			anchored := time.Date(2000, 1, 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
			return &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
				Weekly: &v1.KeyfactorCommonSchedulingModelsWeeklyModel{Days: days, Time: &anchored},
			}, nil
		}
		// Both empty: the weekly clear sentinel. Contributes nothing, same as a
		// fully-undeclared schedule.
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
	return enumPtrToTfInt64(v)
}

// keyRetentionPtrToTfInt64 converts a *CSSCMSCoreEnumsKeyRetentionPolicy pointer to types.Int64.
// Nil (server field absent) becomes Null so the value is not sent on PUT.
func keyRetentionPtrToTfInt64(v *v1.CSSCMSCoreEnumsKeyRetentionPolicy) types.Int64 {
	return enumPtrToTfInt64(v)
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
	return enumPtrToTfInt64(v)
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
	// as an Interval, a Daily, or a Weekly schedule (mutually exclusive, enforced by
	// ValidateConfig at plan time). buildSchedule returns nil for a set that is
	// entirely Null (or only sentinel-valued), which — per Command's full-replace PUT
	// semantics — omits the field from the request and clears it server-side;
	// preserveCAUpdateFields is what prevents that from happening on an Update() that
	// simply didn't declare the attribute.
	fullScan, err := buildSchedule(ctx, plan.FullScanIntervalMinutes, plan.FullScanDailyTime, plan.FullScanWeeklyDays, plan.FullScanWeeklyTime)
	if err != nil {
		diags.AddAttributeError(path.Root("full_scan_weekly_time"), "Invalid full_scan schedule", err.Error())
	} else {
		req.FullScan = fullScan
	}
	incrementalScan, err := buildSchedule(ctx, plan.IncrementalScanIntervalMinutes, plan.IncrementalScanDailyTime, plan.IncrementalScanWeeklyDays, plan.IncrementalScanWeeklyTime)
	if err != nil {
		diags.AddAttributeError(path.Root("incremental_scan_weekly_time"), "Invalid incremental_scan schedule", err.Error())
	} else {
		req.IncrementalScan = incrementalScan
	}
	thresholdCheck, err := buildSchedule(ctx, plan.ThresholdCheckIntervalMinutes, plan.ThresholdCheckDailyTime, plan.ThresholdCheckWeeklyDays, plan.ThresholdCheckWeeklyTime)
	if err != nil {
		diags.AddAttributeError(path.Root("threshold_check_weekly_time"), "Invalid threshold_check schedule", err.Error())
	} else {
		req.ThresholdCheck = thresholdCheck
	}

	return req, diags
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

// preserveSecrets copies write-only secret fields from source (plan or prior
// state) into the target state. These fields (explicit_password,
// auth_certificate, auth_certificate_password, client_secret, force_save) are
// never returned by the server in any form, so there is no server truth to
// prefer over the previously-known value.
//
// allowed_requesters is NOT handled here (as of Command v25.5+, confirmed
// live: GET /CertificateAuthority returns both UseAllowedRequesters and
// AllowedRequesters with real values). caResponseToState already maps the
// server's list into state, so echoing plan/state over it here would mask
// genuine out-of-band drift (e.g. a role removed from the allowed-requester
// list directly in Command) behind a silently "corrected" Read. See G3 in
// the attribute contract: Read must surface server truth for any attribute
// the server can actually report.
func preserveSecrets(target *KeyfactorCertificateAuthority, source KeyfactorCertificateAuthority) {
	target.ExplicitPassword = source.ExplicitPassword
	target.AuthCertificate = source.AuthCertificate
	target.AuthCertificatePassword = source.AuthCertificatePassword
	target.ClientSecret = source.ClientSecret
	target.ForceSave = source.ForceSave
}

// preserveCAUpdateFields reconciles Update() plan values that Command's CA PUT
// treats as full-replace (an omitted field is cleared server-side, not left
// unchanged). For scan/threshold schedules and the allowed-requester list, an
// UNDECLARED attribute means the attribute is simply absent from config, NOT
// that the user wants it cleared — so preserve the prior state value rather
// than letting buildCARequest omit it (which would clear it). This runs only
// on the Update() path; Create() and the Delete() clear-schedule path
// intentionally still let an undeclared value omit/clear.
//
// Declared-ness is keyed on declaredInConfig(config.X) — request.Config, NOT
// plan.X.Null — per the attribute contract in attribute_contract.go: these
// attributes are Optional+Computed with a pairedVariantModifier (schedules) or
// UseStateForUnknown (allowed_requesters) plan modifier, so an undeclared
// attribute's Plan value is usually already resolved to the prior state (not
// Null) by the time this function runs. Checking plan.X.Null would therefore
// only catch the case where state was ALSO already Null (nothing to preserve
// either way) and silently miss any case where a plan modifier resolves an
// undeclared attribute to something other than the literal prior state —
// e.g. pairedVariantModifier deliberately plans the SIBLING of a
// config-declared variant to explicit Null (see F182-1), which is a
// perfectly valid "declared" plan.Null that must NOT be mistaken for
// "undeclared, go preserve state." Config is never touched by plan
// modifiers, so it is the only signal that survives that class of change.
//
// preserveSchedule handles one of FullScan/IncrementalScan/ThresholdCheck,
// each of which can be represented as either an Interval or a Daily value
// (mutually exclusive). "Declared" for the PAIR means EITHER variant is
// declared in config — including a variant switch (e.g. config declares only
// full_scan_daily_time; full_scan_interval_minutes is undeclared but its
// sibling is, so the pair as a whole is user-managed and must NOT be
// preserved from state, or the switch away from Interval would never take
// effect). Only when NEITHER variant is declared in config do we copy
// whichever variant prior state actually holds into the plan, so an
// unrelated Update does not clear a real schedule Command is already
// running.
//
// When the pair IS declared (a variant switch), the undeclared half is
// explicitly forced to Null on the plan rather than left as-is. This is
// deliberate defense-in-depth for F182-1: pairedVariantModifier is what
// normally prevents the undeclared half from carrying a stale/resurrected
// prior-state value forward, but this function does not trust that to be the
// only thing standing between a resurrected plan value and the outgoing PUT
// — forcing it here means a variant switch sends exactly one of
// Interval/Daily to Command regardless of what produced the incoming plan
// value. Note this is superseded for the wire request body by the
// read-modify-write in Update (see the GET-before-PUT block there), which
// also protects schedule variants this provider does not model
// (Weekly/Monthly/ExactlyOnce/Immediate); this function still matters for
// keeping plan/state internally coherent and for the Delete() force-save
// error path, which calls buildCARequest directly without the GET step.
//
// Note on allowed_requesters: on Command v25.5+ (confirmed live), GET
// /CertificateAuthority reports the real list, so caResponseToState
// (state, prior to this function running) generally already carries a real
// value to preserve here — including after ImportState. On older Command
// versions that do not return the list on GET, the prior state may itself be
// Null and there is nothing to preserve; in that case the field remains
// omitted from the request, relying on Command to leave an omitted
// AllowedRequesters unchanged.
func preserveCAUpdateFields(ctx context.Context, plan *KeyfactorCertificateAuthority, config, state KeyfactorCertificateAuthority) {
	preserveSchedule := func(name string,
		planInterval *types.Int64, planDaily *types.String, planWeeklyDays *types.List, planWeeklyTime *types.String,
		configInterval types.Int64, configDaily types.String, configWeeklyDays types.List, configWeeklyTime types.String,
		stateInterval types.Int64, stateDaily types.String, stateWeeklyDays types.List, stateWeeklyTime types.String,
	) {
		anyDeclared := declaredInConfig(configInterval) || declaredInConfig(configDaily) ||
			declaredInConfig(configWeeklyDays) || declaredInConfig(configWeeklyTime)
		if anyDeclared {
			if !declaredInConfig(configInterval) {
				*planInterval = types.Int64{Null: true}
			}
			if !declaredInConfig(configDaily) {
				*planDaily = types.String{Null: true}
			}
			if !declaredInConfig(configWeeklyDays) {
				*planWeeklyDays = types.List{Null: true, ElemType: types.StringType}
			}
			if !declaredInConfig(configWeeklyTime) {
				*planWeeklyTime = types.String{Null: true}
			}
			tflog.Debug(ctx, fmt.Sprintf("preserveCAUpdateFields: %s schedule declared in config -- managed, enforcing config truth on plan", name))
			return
		}
		if !stateInterval.Null && !stateInterval.Unknown {
			*planInterval = stateInterval
		}
		if !stateDaily.Null && !stateDaily.Unknown {
			*planDaily = stateDaily
		}
		if !stateWeeklyDays.Null && !stateWeeklyDays.Unknown {
			*planWeeklyDays = stateWeeklyDays
		}
		if !stateWeeklyTime.Null && !stateWeeklyTime.Unknown {
			*planWeeklyTime = stateWeeklyTime
		}
		tflog.Debug(ctx, fmt.Sprintf("preserveCAUpdateFields: %s schedule undeclared in config -- preserving prior state value on plan", name))
	}
	preserveSchedule("full_scan",
		&plan.FullScanIntervalMinutes, &plan.FullScanDailyTime, &plan.FullScanWeeklyDays, &plan.FullScanWeeklyTime,
		config.FullScanIntervalMinutes, config.FullScanDailyTime, config.FullScanWeeklyDays, config.FullScanWeeklyTime,
		state.FullScanIntervalMinutes, state.FullScanDailyTime, state.FullScanWeeklyDays, state.FullScanWeeklyTime)
	preserveSchedule("incremental_scan",
		&plan.IncrementalScanIntervalMinutes, &plan.IncrementalScanDailyTime, &plan.IncrementalScanWeeklyDays, &plan.IncrementalScanWeeklyTime,
		config.IncrementalScanIntervalMinutes, config.IncrementalScanDailyTime, config.IncrementalScanWeeklyDays, config.IncrementalScanWeeklyTime,
		state.IncrementalScanIntervalMinutes, state.IncrementalScanDailyTime, state.IncrementalScanWeeklyDays, state.IncrementalScanWeeklyTime)
	preserveSchedule("threshold_check",
		&plan.ThresholdCheckIntervalMinutes, &plan.ThresholdCheckDailyTime, &plan.ThresholdCheckWeeklyDays, &plan.ThresholdCheckWeeklyTime,
		config.ThresholdCheckIntervalMinutes, config.ThresholdCheckDailyTime, config.ThresholdCheckWeeklyDays, config.ThresholdCheckWeeklyTime,
		state.ThresholdCheckIntervalMinutes, state.ThresholdCheckDailyTime, state.ThresholdCheckWeeklyDays, state.ThresholdCheckWeeklyTime)

	if !declaredInConfig(config.AllowedRequesters) && !state.AllowedRequesters.Null && !state.AllowedRequesters.Unknown {
		plan.AllowedRequesters = state.AllowedRequesters
		tflog.Debug(ctx, "preserveCAUpdateFields: allowed_requesters undeclared in config -- preserving prior state value on plan")
	}
}

// applyUndeclaredScheduleFallback is the F182-3 read-modify-write guard: for
// each of FullScan/IncrementalScan/ThresholdCheck, if config declares NONE of
// the Interval, Daily, or Weekly variants, overwrite whatever buildCARequest
// put on updateReq with the server's CURRENT schedule from a fresh GET
// (getResp), verbatim. This is what actually protects schedule variants this
// provider does not model at all (Monthly/ExactlyOnce/Immediate) -- unlike
// preserveCAUpdateFields, which can only fall back to a prior STATE value that
// scheduleToState may have already collapsed to Null for exactly those
// variants. request and response share the same
// v1.KeyfactorCommonSchedulingKeyfactorSchedule type, so this is also a safe
// no-op for a config-declared Interval/Daily/Weekly pair's sibling schedules
// and for a genuinely undeclared-and-never-configured schedule (getResp's
// field is nil either way).
func applyUndeclaredScheduleFallback(ctx context.Context, updateReq *v1.CertificateAuthoritiesCertificateAuthorityRequest, config KeyfactorCertificateAuthority, getResp *v1.CertificateAuthoritiesCertificateAuthorityResponse) {
	if getResp == nil {
		return
	}
	if !declaredInConfig(config.FullScanIntervalMinutes) && !declaredInConfig(config.FullScanDailyTime) &&
		!declaredInConfig(config.FullScanWeeklyDays) && !declaredInConfig(config.FullScanWeeklyTime) {
		updateReq.FullScan = getResp.FullScan
		tflog.Debug(ctx, "applyUndeclaredScheduleFallback: full_scan undeclared in config -- copying current server schedule verbatim onto the request")
	}
	if !declaredInConfig(config.IncrementalScanIntervalMinutes) && !declaredInConfig(config.IncrementalScanDailyTime) &&
		!declaredInConfig(config.IncrementalScanWeeklyDays) && !declaredInConfig(config.IncrementalScanWeeklyTime) {
		updateReq.IncrementalScan = getResp.IncrementalScan
		tflog.Debug(ctx, "applyUndeclaredScheduleFallback: incremental_scan undeclared in config -- copying current server schedule verbatim onto the request")
	}
	if !declaredInConfig(config.ThresholdCheckIntervalMinutes) && !declaredInConfig(config.ThresholdCheckDailyTime) &&
		!declaredInConfig(config.ThresholdCheckWeeklyDays) && !declaredInConfig(config.ThresholdCheckWeeklyTime) {
		updateReq.ThresholdCheck = getResp.ThresholdCheck
		tflog.Debug(ctx, "applyUndeclaredScheduleFallback: threshold_check undeclared in config -- copying current server schedule verbatim onto the request")
	}
}

// keepScheduleSentinels implements sentinel stability (attribute contract
// item 4, G2) for the three CA schedules: 0 for *_interval_minutes, "" for
// *_daily_time, and the pair ([] + "") for *_weekly_days/*_weekly_time are
// declarative "clear this schedule" sentinels (see buildSchedule).
// scheduleToState cannot tell "the user cleared this schedule with a
// sentinel" apart from "the server genuinely has no schedule here" or "the
// server holds a variant this provider does not model" -- all collapse to
// (Null, Null, Null, Null). Left alone, that would mean a declared
// `full_scan_interval_minutes = 0` never actually settles: Read/Update would
// write state back as Null, and the next plan would show a spurious
// `0 -> null -> 0` diff forever, because Optional+Computed with
// pairedVariantModifier plans the config-declared value (0) again every time
// state disagrees with it.
//
// When newState reports no schedule at all (all four Null) and the caller's
// prior value (plan on Create/Update, prior state on Read) was itself a
// sentinel, carry that same sentinel forward into newState instead of
// leaving it Null -- this is the only case this function touches. If
// newState reports a REAL value for the schedule, it is left alone: that is
// genuine drift (or the schedule the user just set), and must not be masked
// by a stale sentinel from before.
//
// This is CA-specific (not a generic attribute_contract.go helper like
// declaredInConfig/pairedVariantModifier) because it operates directly on the
// three concrete KeyfactorCertificateAuthority schedules rather than a
// single generic attr.Value.
func keepScheduleSentinels(ctx context.Context, newState *KeyfactorCertificateAuthority, prior KeyfactorCertificateAuthority) {
	keep := func(name string,
		newInterval *types.Int64, newDaily *types.String, newWeeklyDays *types.List, newWeeklyTime *types.String,
		priorInterval types.Int64, priorDaily types.String, priorWeeklyDays types.List, priorWeeklyTime types.String,
	) {
		if !newInterval.Null || !newDaily.Null || !newWeeklyDays.Null || !newWeeklyTime.Null {
			return
		}
		if !priorInterval.Null && !priorInterval.Unknown && priorInterval.Value == 0 {
			*newInterval = types.Int64{Value: 0}
			tflog.Debug(ctx, fmt.Sprintf("keepScheduleSentinels: %s reported no schedule -- carrying forward the declared interval=0 clear sentinel", name))
			return
		}
		if !priorDaily.Null && !priorDaily.Unknown && priorDaily.Value == "" {
			*newDaily = types.String{Value: ""}
			tflog.Debug(ctx, fmt.Sprintf("keepScheduleSentinels: %s reported no schedule -- carrying forward the declared daily=\"\" clear sentinel", name))
			return
		}
		if !priorWeeklyDays.Null && !priorWeeklyDays.Unknown && !priorWeeklyTime.Null && !priorWeeklyTime.Unknown && priorWeeklyTime.Value == "" {
			var days []string
			priorWeeklyDays.ElementsAs(ctx, &days, false)
			if len(days) == 0 {
				*newWeeklyDays = stringSliceToTfList(nil)
				*newWeeklyTime = types.String{Value: ""}
				tflog.Debug(ctx, fmt.Sprintf("keepScheduleSentinels: %s reported no schedule -- carrying forward the declared weekly=([]+\"\") clear sentinel", name))
			}
		}
	}
	keep("full_scan",
		&newState.FullScanIntervalMinutes, &newState.FullScanDailyTime, &newState.FullScanWeeklyDays, &newState.FullScanWeeklyTime,
		prior.FullScanIntervalMinutes, prior.FullScanDailyTime, prior.FullScanWeeklyDays, prior.FullScanWeeklyTime)
	keep("incremental_scan",
		&newState.IncrementalScanIntervalMinutes, &newState.IncrementalScanDailyTime, &newState.IncrementalScanWeeklyDays, &newState.IncrementalScanWeeklyTime,
		prior.IncrementalScanIntervalMinutes, prior.IncrementalScanDailyTime, prior.IncrementalScanWeeklyDays, prior.IncrementalScanWeeklyTime)
	keep("threshold_check",
		&newState.ThresholdCheckIntervalMinutes, &newState.ThresholdCheckDailyTime, &newState.ThresholdCheckWeeklyDays, &newState.ThresholdCheckWeeklyTime,
		prior.ThresholdCheckIntervalMinutes, prior.ThresholdCheckDailyTime, prior.ThresholdCheckWeeklyDays, prior.ThresholdCheckWeeklyTime)
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
	// Sentinel stability (G2): a declared clear sentinel (interval 0 / daily
	// "") on Create produces no schedule server-side, which caResponseToState
	// reports as (Null, Null) -- indistinguishable from "never configured".
	// Carry the declared sentinel into state so the very next plan does not
	// see a spurious null -> 0 diff against the config that is still
	// declaring 0.
	keepScheduleSentinels(ctx, &state, plan)

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
	// Sentinel stability (G2): if the server reports no schedule at all for a
	// pair and the prior state was a declared clear sentinel, keep the
	// sentinel rather than surfacing a Null that would otherwise look like
	// drift away from what the user declared.
	keepScheduleSentinels(ctx, &newState, state)

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

	// Get config values. The scan/threshold schedules and allowed_requesters
	// are Optional+Computed, so request.Plan is no longer a reliable signal
	// of whether the user actually declared them (see preserveCAUpdateFields'
	// doc comment and declaredInConfig in attribute_contract.go) —
	// request.Config is.
	var config KeyfactorCertificateAuthority
	diags = request.Config.Get(ctx, &config)
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

	caAPI := r.p.sdkClient.V1.CertificateAuthorityApi

	// Read-modify-write guard for schedule variants this provider does not
	// model (Weekly/Monthly/ExactlyOnce/Immediate): preserveCAUpdateFields and
	// buildSchedule can only reconstruct the Interval/Daily variants they have
	// attribute pairs for, and scheduleToState collapses any other variant to
	// Null in state (see its doc comment) -- so a schedule pair left entirely
	// undeclared in config has no state value to preserve either. GET the CA
	// fresh right before the PUT and, for any schedule pair config does not
	// declare, copy the server's CURRENT schedule verbatim into the request
	// below (see applyUndeclaredScheduleFallback) -- the request and response
	// share the same v1.KeyfactorCommonSchedulingKeyfactorSchedule type, so
	// this transparently covers Weekly/Monthly/ExactlyOnce/Immediate as well
	// as being a no-op for Interval/Daily (buildSchedule already reconstructed
	// the same shape from plan/preserveCAUpdateFields there). A GET error here
	// is treated as fatal rather than falling back to a blind PUT, since a
	// blind PUT for an undeclared schedule pair risks silently clearing
	// whatever variant the server currently holds.
	//
	// Known edge: this GET happens moments before the PUT, not at the start
	// of the Terraform run, so `terraform apply -refresh=false` racing an
	// out-of-band schedule change between the last Read and this Update can
	// still see a one-time "Provider produced inconsistent result after
	// apply" if the two disagree -- the next Read/plan reconciles it. This is
	// an accepted, narrow window; the alternative (trusting in-memory state
	// for a schedule variant this provider cannot represent at all) is
	// strictly worse.
	getResp, getHTTPResp, err := caAPI.NewGetCertificateAuthorityByIdRequest(ctx, int32(id)).Execute()
	if err != nil {
		body := readHTTPResponseBody(getHTTPResp)
		response.Diagnostics.AddError(
			"Error updating certificate authority.",
			fmt.Sprintf("Could not read current state of certificate authority %d before update: %s. Details: %s", id, err.Error(), body),
		)
		return
	}

	// Command's CA PUT is a full replacement: any scan/threshold schedule or
	// allowed-requester list omitted from the body is cleared server-side (the
	// Delete path below deliberately exploits this to clear Windows Task
	// Scheduler entries). buildCARequest omits FullScan/IncrementalScan/
	// ThresholdCheck/AllowedRequesters whenever the plan value is Null. On an
	// Update() that leaves those attributes undeclared this silently wipes a
	// live schedule or the CA's real allowed-requester list. Mirror GH issue
	// #175: preserve the prior state value when config simply does not
	// declare the attribute, so an unrelated Update never clears state the
	// user never asked to change.
	preserveCAUpdateFields(ctx, &plan, config, state)

	updateReq, buildDiags := buildCARequest(ctx, plan)
	response.Diagnostics.Append(buildDiags...)
	if response.Diagnostics.HasError() {
		return
	}
	idInt32 := int32(id)
	updateReq.Id = &idInt32
	applyUndeclaredScheduleFallback(ctx, &updateReq, config, getResp)

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
	// Sentinel stability (G2): a config-declared clear sentinel omits the
	// field from the PUT (see buildSchedule), so the server reports no
	// schedule and caResponseToState collapses it to (Null, Null). Carry the
	// planned sentinel forward so the next plan sees the same declared 0/""
	// reflected back, not a spurious diff against Null.
	keepScheduleSentinels(ctx, &newState, plan)

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
			clearState.FullScanWeeklyDays = types.List{Null: true, ElemType: types.StringType}
			clearState.FullScanWeeklyTime = types.String{Null: true}
			clearState.IncrementalScanIntervalMinutes = types.Int64{Null: true}
			clearState.IncrementalScanDailyTime = types.String{Null: true}
			clearState.IncrementalScanWeeklyDays = types.List{Null: true, ElemType: types.StringType}
			clearState.IncrementalScanWeeklyTime = types.String{Null: true}
			clearState.ThresholdCheckIntervalMinutes = types.Int64{Null: true}
			clearState.ThresholdCheckDailyTime = types.String{Null: true}
			clearState.ThresholdCheckWeeklyDays = types.List{Null: true, ElemType: types.StringType}
			clearState.ThresholdCheckWeeklyTime = types.String{Null: true}
			clearReq, buildDiags := buildCARequest(ctx, clearState)
			response.Diagnostics.Append(buildDiags...)
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

// ValidateConfig enforces that each of the three schedules (full_scan,
// incremental_scan, threshold_check) is declared using at most one of its three
// supported representations — Interval (*_interval_minutes), Daily (*_daily_time), or
// Weekly (*_weekly_days + *_weekly_time) — matching Command's own KeyfactorSchedule
// model, where these are mutually exclusive variants of a single schedule, never more
// than one at once. It also validates that any *_daily_time/*_weekly_time value is a
// parseable UTC time-of-day (caDailyTimeLayout), since buildSchedule assumes that by
// the time it runs.
func (r resourceCertificateAuthority) ValidateConfig(ctx context.Context, request tfsdk.ValidateResourceConfigRequest, response *tfsdk.ValidateResourceConfigResponse) {
	var cfg KeyfactorCertificateAuthority
	diags := request.Config.Get(ctx, &cfg)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	scheduleDiags := validateCAScheduleAttributes(ctx, cfg)
	for _, d := range scheduleDiags {
		// tflog.Warn alongside every AddAttributeError this produces (mirrors
		// the Delete path's tflog.Warn-before-AddError pattern above): the
		// diagnostic itself is what Terraform Core surfaces to the
		// practitioner, but a provider-log trail of exactly which schedule
		// attribute failed and why is useful when debugging a CI plan/apply
		// where the CLI's rendered diagnostic text is all that's captured.
		tflog.Warn(ctx, fmt.Sprintf("certificate authority schedule validation error: %s: %s", d.Summary(), d.Detail()))
	}
	response.Diagnostics.Append(scheduleDiags...)

	constraintDiags := validateCAConfigConstraints(cfg)
	for _, d := range constraintDiags {
		tflog.Warn(ctx, fmt.Sprintf("certificate authority config constraint validation error: %s: %s", d.Summary(), d.Detail()))
	}
	response.Diagnostics.Append(constraintDiags...)
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
//
// Every check here follows the same declaredInConfig-style discipline as
// validateCAScheduleAttributes: a null or unknown value is never an error,
// since config-time validation cannot resolve a value that isn't known yet
// (e.g. standalone referencing another resource's not-yet-known output), and
// ValidateConfig only ever sees Config, never Plan/State. Only an explicitly
// configured, known violation is rejected. Factored out of ValidateConfig so
// it can be unit tested directly against a KeyfactorCertificateAuthority
// value, matching validateCAScheduleAttributes's precedent.
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

	// F4: allowed_enrollment_types, use_allowed_requesters, and
	// allowed_requesters all apply to standalone CAs only -- only an issue
	// when standalone is explicitly declared false; standalone left
	// undeclared/unknown never trips this (config-time validation can't
	// resolve a computed/unresolved standalone value).
	standaloneKnown := !cfg.Standalone.Null && !cfg.Standalone.Unknown
	if standaloneKnown && !cfg.Standalone.Value {
		if !cfg.AllowedEnrollmentTypes.Null && !cfg.AllowedEnrollmentTypes.Unknown {
			diags.AddAttributeError(
				path.Root("allowed_enrollment_types"),
				"Invalid certificate authority attribute for a non-standalone CA",
				"allowed_enrollment_types requires standalone=true.",
			)
		}
		if !cfg.UseAllowedRequesters.Null && !cfg.UseAllowedRequesters.Unknown {
			diags.AddAttributeError(
				path.Root("use_allowed_requesters"),
				"Invalid certificate authority attribute for a non-standalone CA",
				"use_allowed_requesters applies to standalone CAs only.",
			)
		}
		if !cfg.AllowedRequesters.Null && !cfg.AllowedRequesters.Unknown {
			diags.AddAttributeError(
				path.Root("allowed_requesters"),
				"Invalid certificate authority attribute for a non-standalone CA",
				"allowed_requesters applies to standalone CAs only.",
			)
		}
	}

	return diags
}

// scheduleVariants names one of the three CA schedules (full_scan, incremental_scan,
// threshold_check) and its three mutually exclusive attribute representations --
// Interval, Daily, and Weekly (a co-required pair, weeklyDaysAttr/weeklyTimeAttr).
type scheduleVariants struct {
	name           string
	intervalAttr   string
	dailyAttr      string
	weeklyDaysAttr string
	weeklyTimeAttr string
	interval       types.Int64
	daily          types.String
	weeklyDays     types.List
	weeklyTime     types.String
}

func caScheduleVariants(cfg KeyfactorCertificateAuthority) []scheduleVariants {
	return []scheduleVariants{
		{
			"full_scan", "full_scan_interval_minutes", "full_scan_daily_time", "full_scan_weekly_days", "full_scan_weekly_time",
			cfg.FullScanIntervalMinutes, cfg.FullScanDailyTime, cfg.FullScanWeeklyDays, cfg.FullScanWeeklyTime,
		},
		{
			"incremental_scan", "incremental_scan_interval_minutes", "incremental_scan_daily_time", "incremental_scan_weekly_days", "incremental_scan_weekly_time",
			cfg.IncrementalScanIntervalMinutes, cfg.IncrementalScanDailyTime, cfg.IncrementalScanWeeklyDays, cfg.IncrementalScanWeeklyTime,
		},
		{
			"threshold_check", "threshold_check_interval_minutes", "threshold_check_daily_time", "threshold_check_weekly_days", "threshold_check_weekly_time",
			cfg.ThresholdCheckIntervalMinutes, cfg.ThresholdCheckDailyTime, cfg.ThresholdCheckWeeklyDays, cfg.ThresholdCheckWeeklyTime,
		},
	}
}

// validateCAScheduleAttributes enforces that each of the three schedules
// (full_scan, incremental_scan, threshold_check) is declared using at most one of
// its three supported representations — Interval (*_interval_minutes), Daily
// (*_daily_time), or Weekly (*_weekly_days + *_weekly_time) — matching Command's own
// KeyfactorSchedule model, where these are mutually exclusive variants of a single
// schedule, never more than one at once. It also validates that any *_daily_time or
// *_weekly_time value is a parseable UTC time-of-day (caDailyTimeLayout, "HH:MM:SS"),
// that *_weekly_days names are exact, case-sensitive day names, and that the weekly
// pair is co-required (declaring one without the other is an error) -- since
// buildSchedule assumes all of this by the time it runs. Factored out of
// ValidateConfig so it can be unit tested directly against a
// KeyfactorCertificateAuthority value, without needing to construct the framework's
// tfsdk.Config plumbing.
func validateCAScheduleAttributes(ctx context.Context, cfg KeyfactorCertificateAuthority) diag.Diagnostics {
	var diags diag.Diagnostics

	for _, p := range caScheduleVariants(cfg) {
		intervalKnown := !p.interval.Null && !p.interval.Unknown
		dailyKnown := !p.daily.Null && !p.daily.Unknown
		weeklyDaysKnown := !p.weeklyDays.Null && !p.weeklyDays.Unknown
		weeklyTimeKnown := !p.weeklyTime.Null && !p.weeklyTime.Unknown
		weeklyKnown := weeklyDaysKnown && weeklyTimeKnown

		// Weekly's two attributes are co-required: declaring one without the
		// other is ambiguous (is it a partial real schedule or a partial
		// clear?) and rejected regardless of whether the declared half is a
		// sentinel or a real value.
		if weeklyDaysKnown != weeklyTimeKnown {
			diags.AddAttributeError(
				path.Root(p.weeklyTimeAttr),
				fmt.Sprintf("Incomplete %s weekly schedule", p.name),
				fmt.Sprintf("%s and %s must be set together (co-required); got only one of the pair.", p.weeklyDaysAttr, p.weeklyTimeAttr),
			)
		}

		variantsDeclared := 0
		if intervalKnown {
			variantsDeclared++
		}
		if dailyKnown {
			variantsDeclared++
		}
		if weeklyKnown {
			variantsDeclared++
		}

		// More than one variant declared is still a conflict regardless of
		// whether any side is the G2 clear sentinel (interval 0 / daily "" /
		// weekly [] + "") -- a sentinel is a real, declared value like any
		// other, so declaring a sentinel alongside a real value (or two
		// sentinels) on the same schedule is exactly as ambiguous as
		// declaring two real values.
		if variantsDeclared > 1 {
			diags.AddAttributeError(
				path.Root(p.dailyAttr),
				fmt.Sprintf("Conflicting %s schedule attributes", p.name),
				fmt.Sprintf(
					"%s, %s, and %s/%s all represent the %s schedule and are mutually exclusive (Command models a schedule as an interval, a daily time, or a weekly days+time, never more than one). Set at most one representation.",
					p.intervalAttr, p.dailyAttr, p.weeklyDaysAttr, p.weeklyTimeAttr, p.name,
				),
			)
		}

		// G2: 0 is the declarative "clear this schedule" sentinel for
		// *_interval_minutes; any other negative value is simply invalid
		// (Command does not support negative intervals).
		if intervalKnown && p.interval.Value < 0 {
			diags.AddAttributeError(
				path.Root(p.intervalAttr),
				fmt.Sprintf("Invalid %s value", p.intervalAttr),
				fmt.Sprintf("%s must be zero (to clear the schedule) or a positive interval in minutes; got %d", p.intervalAttr, p.interval.Value),
			)
		}

		// G2: "" is the declarative "clear this schedule" sentinel for
		// *_daily_time; skip the time-of-day parse for it, since it is not
		// meant to be a timestamp at all.
		if dailyKnown && p.daily.Value != "" {
			if _, err := time.Parse(caDailyTimeLayout, p.daily.Value); err != nil {
				diags.AddAttributeError(
					path.Root(p.dailyAttr),
					fmt.Sprintf("Invalid %s value", p.dailyAttr),
					fmt.Sprintf("%s must be a UTC time-of-day formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), or \"\" to clear the schedule; got %q: %s", p.dailyAttr, p.daily.Value, err.Error()),
				)
			}
		}

		// Weekly: validate day names and time-of-day format. G2: [] + "" is
		// the declarative "clear this schedule" sentinel for the weekly pair
		// -- an empty days list skips the day-name validation below (there
		// is nothing to validate), and an empty time skips the time-of-day
		// parse, for the same reason the daily "" sentinel does.
		if weeklyKnown {
			var dayNames []string
			diags.Append(p.weeklyDays.ElementsAs(ctx, &dayNames, false)...)
			for _, n := range dayNames {
				if _, err := caDayNamesToEnums([]string{n}); err != nil {
					diags.AddAttributeError(
						path.Root(p.weeklyDaysAttr),
						fmt.Sprintf("Invalid %s value", p.weeklyDaysAttr),
						err.Error(),
					)
				}
			}
			if p.weeklyTime.Value != "" {
				if _, err := time.Parse(caDailyTimeLayout, p.weeklyTime.Value); err != nil {
					diags.AddAttributeError(
						path.Root(p.weeklyTimeAttr),
						fmt.Sprintf("Invalid %s value", p.weeklyTimeAttr),
						fmt.Sprintf("%s must be a UTC time-of-day formatted \"HH:MM:SS\" (e.g. \"07:00:00\"), or \"\" to clear the schedule; got %q: %s", p.weeklyTimeAttr, p.weeklyTime.Value, err.Error()),
					)
				}
			}
			// A mismatched pair (one sentinel, one real) is ambiguous --
			// same rationale as buildSchedule's defense-in-depth check.
			if (len(dayNames) == 0) != (p.weeklyTime.Value == "") {
				diags.AddAttributeError(
					path.Root(p.weeklyTimeAttr),
					fmt.Sprintf("Mismatched %s weekly schedule", p.name),
					fmt.Sprintf("%s and %s must either both be set to real values or both be empty (to clear the schedule); got a mismatched pair.", p.weeklyDaysAttr, p.weeklyTimeAttr),
				)
			}
		}
	}

	return diags
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
//  2. Plan is Unknown (properties undeclared in config, Computed-only) --
//     fall back to plain UseStateForUnknown semantics: copy state forward.
//  3. Plan and state are both known strings and, once parsed and
//     re-marshaled, are semantically equal -- keep the prior state value
//     (byte-for-byte) so the diff (and the Update PUT) disappears.
//  4. Otherwise (a genuine value change, or either side isn't a comparable
//     JSON string) -- leave the plan as computed, surfacing a real diff.
type normalizedJSONPropertiesModifier struct{}

func (m normalizedJSONPropertiesModifier) Description(_ context.Context) string {
	return "Suppresses a properties diff when the server's stored JSON differs from state only in key order/whitespace."
}

func (m normalizedJSONPropertiesModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m normalizedJSONPropertiesModifier) Modify(_ context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeState == nil || resp.AttributePlan == nil {
		return
	}
	stateVal, ok := req.AttributeState.(types.String)
	if !ok || stateVal.Unknown {
		// No usable prior state (e.g. Create) -- nothing to compare against.
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
