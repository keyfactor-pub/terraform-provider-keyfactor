package keyfactor

import (
	"context"
	"strings"
	"testing"
	"time"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Unit tests — CA Daily-schedule variant support
//
// Command represents each of full_scan/incremental_scan/threshold_check as a
// KeyfactorSchedule tagged union that can be Interval-shaped or Daily-shaped.
// Before this fix, caResponseToState only understood Interval, so a
// Daily-shaped schedule read back as Null -- indistinguishable from "no
// schedule at all." Since the update endpoint is a full-replace PUT, an
// omitted schedule field clears it server-side, so any CA using a Daily
// schedule had it silently wiped on every apply, not just the first one.
// Confirmed live against a real lab CA using a Daily full_scan schedule: an
// ordinary import + apply cleared it.
// ---------------------------------------------------------------------------

// blankCAConfig returns a KeyfactorCertificateAuthority with every attribute
// explicitly set to a well-typed value (Required attributes get a concrete
// value; every Optional/Computed attribute is explicit Null, including the
// only List-typed attribute, which additionally needs its ElemType set). This
// is a test-only helper so callers can flip just the field(s) under test
// without hand-populating ~40 unrelated struct fields, while still producing
// a struct that tfsdk.Plan.Set / tfsdk.Config-via-Plan.Set can serialize
// without a schema/type mismatch.
func blankCAConfig() KeyfactorCertificateAuthority {
	nullStr := types.String{Null: true}
	nullBool := types.Bool{Null: true}
	nullInt := types.Int64{Null: true}
	return KeyfactorCertificateAuthority{
		ID:                             nullStr,
		LogicalName:                    types.String{Value: "Test-CA"},
		HostName:                       types.String{Value: "http://ca.example.com/ejbca"},
		CAType:                         types.Int64{Value: 1},
		Delegate:                       nullBool,
		DelegateEnrollment:             nullBool,
		ForestRoot:                     nullStr,
		ConfigurationTenant:            nullStr,
		Remote:                         nullBool,
		Agent:                          nullStr,
		Standalone:                     nullBool,
		UseCAConnector:                 nullBool,
		ConnectorPool:                  nullStr,
		MonitorThresholds:              nullBool,
		IssuanceMax:                    nullInt,
		IssuanceMin:                    nullInt,
		FailureMax:                     nullInt,
		RFCEnforcement:                 nullBool,
		Properties:                     nullStr,
		AllowedEnrollmentTypes:         nullInt,
		KeyRetention:                   nullStr,
		KeyRetentionDays:               nullInt,
		EnforceUniqueDN:                nullBool,
		SubscriberTerms:                nullBool,
		AllowOneClickRenewals:          nullBool,
		NewEndEntityOnRenewAndReissue:  nullBool,
		UseForEnrollment:               nullBool,
		CertificateCleanupEnabled:      nullBool,
		DeleteWithArchivedKey:          nullBool,
		TimeAfterExpiration:            nullInt,
		TimeAfterExpirationUnits:       nullInt,
		UseAllowedRequesters:           nullBool,
		AllowedRequesters:              types.List{Null: true, ElemType: types.StringType},
		ExplicitCredentials:            nullBool,
		ExplicitUser:                   nullStr,
		ExplicitPassword:               nullStr,
		AuthCertificate:                nullStr,
		AuthCertificatePassword:        nullStr,
		AuthCertificateIssuedDN:        nullStr,
		AuthCertificateIssuerDN:        nullStr,
		AuthCertificateThumbprint:      nullStr,
		TokenURL:                       nullStr,
		ClientID:                       nullStr,
		ClientSecret:                   nullStr,
		Scope:                          nullStr,
		Audience:                       nullStr,
		FullScanIntervalMinutes:        nullInt,
		FullScanDailyTime:              nullStr,
		IncrementalScanIntervalMinutes: nullInt,
		IncrementalScanDailyTime:       nullStr,
		ThresholdCheckIntervalMinutes:  nullInt,
		ThresholdCheckDailyTime:        nullStr,
		ForceSave:                      nullBool,
		AgentName:                      nullStr,
		AgentUsername:                  nullStr,
		DenialMax:                      nullInt,
		LastScan:                       nullStr,
	}
}

// asConfig round-trips a KeyfactorCertificateAuthority through a tfsdk.Plan
// (which has a .Set method Config lacks in this framework version) and
// reuses the resulting Raw value to build a tfsdk.Config with the same
// underlying representation -- Plan/State/Config are all thin wrappers over
// {Raw tftypes.Value; Schema Schema}.
func asConfig(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateAuthority) tfsdk.Config {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.Config{Schema: schema, Raw: p.Raw}
}

// asState is asConfig's State-typed counterpart, needed by tests exercising
// authVariantSiblingModifier's unknownTriggerPaths (full-review round 4
// finding #1), which compares a trigger path's CONFIG value against its own
// prior STATE value to distinguish an incoming/rotating auth_certificate
// from a steadily-redeclared one.
func asState(t *testing.T, ctx context.Context, schema tfsdk.Schema, v KeyfactorCertificateAuthority) tfsdk.State {
	t.Helper()
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, &v); d.HasError() {
		t.Fatalf("test setup: Plan.Set returned diagnostics: %+v", d)
	}
	return tfsdk.State{Schema: schema, Raw: p.Raw}
}

// ---------------------------------------------------------------------------
// TestUnitCAReadPreservesDailySchedule
// ---------------------------------------------------------------------------

// TestUnitCAReadPreservesDailySchedule is the regression test for the root
// bug: caResponseToState (via scheduleToState) must map a Daily-shaped
// schedule into the new *_daily_time attribute, not collapse it to Null.
// Null is indistinguishable from "no schedule configured," which is exactly
// what caused Command's full-replace update to silently clear a live Daily
// schedule on every apply.
func TestUnitCAReadPreservesDailySchedule(t *testing.T) {
	t.Parallel()

	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	dailyTime := time.Date(2026, 7, 18, 15, 46, 0, 0, time.UTC)

	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(1)
	resp.SetLogicalName("Sub-CA")
	resp.SetHostName("https://ca.lab/ejbca")
	resp.CAType = &caType
	resp.FullScan = &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
		Daily: &v1.KeyfactorCommonSchedulingModelsTimeModel{Time: &dailyTime},
	}

	state := caResponseToState(resp)

	if state.FullScanDailyTime.Null {
		t.Fatalf(
			"FullScanDailyTime: want the Daily schedule's time-of-day, got Null -- this reproduces the root bug: " +
				"a Daily-shaped schedule reads back as indistinguishable from \"no schedule,\" so the next " +
				"full-replace update omits it and Command clears the real, live schedule server-side",
		)
	}
	wantTime := dailyTime.Format(caDailyTimeLayout)
	if state.FullScanDailyTime.Value != wantTime {
		t.Errorf("FullScanDailyTime: want %q, got %q", wantTime, state.FullScanDailyTime.Value)
	}
	if !state.FullScanIntervalMinutes.Null {
		t.Errorf(
			"FullScanIntervalMinutes: want Null (schedule is Daily-shaped, not Interval-shaped), got Value=%v",
			state.FullScanIntervalMinutes.Value,
		)
	}

	// Sanity: an Interval-shaped schedule still maps to *_interval_minutes and
	// leaves *_daily_time Null (no regression on the pre-existing behavior).
	minutes := int32(60)
	resp.IncrementalScan = &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
		Interval: &v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes},
	}
	state = caResponseToState(resp)
	if state.IncrementalScanIntervalMinutes.Null || state.IncrementalScanIntervalMinutes.Value != 60 {
		t.Errorf("IncrementalScanIntervalMinutes: want 60, got Null=%v Value=%v",
			state.IncrementalScanIntervalMinutes.Null, state.IncrementalScanIntervalMinutes.Value)
	}
	if !state.IncrementalScanDailyTime.Null {
		t.Errorf("IncrementalScanDailyTime: want Null (schedule is Interval-shaped), got %q", state.IncrementalScanDailyTime.Value)
	}

	// No schedule configured at all: both must be Null.
	resp.ThresholdCheck = nil
	state = caResponseToState(resp)
	if !state.ThresholdCheckIntervalMinutes.Null || !state.ThresholdCheckDailyTime.Null {
		t.Errorf("ThresholdCheck with nil schedule: want both Null, got IntervalMinutes.Null=%v DailyTime.Null=%v",
			state.ThresholdCheckIntervalMinutes.Null, state.ThresholdCheckDailyTime.Null)
	}
}

// ---------------------------------------------------------------------------
// ValidateConfig regression tests
//
// NOTE: this file's Update()-path preserveCAUpdateFields regression coverage
// (TestUnitCAUpdatePreservesDailySchedule and
// TestUnitCAUpdateScheduleVariantSwitchDoesNotResurrectOther) and most of its
// ValidateConfig-path coverage below were superseded by the Weekly-variant
// extension of the schedule attribute contract (Interval/Daily/Weekly,
// three-way mutual exclusion) -- preserveCAUpdateFields/buildSchedule gained
// a ctx/weekly-days/weekly-time parameter that these tests' 2-arg calls no
// longer match. Equivalent (and Weekly-extended) coverage now lives in
// resource_keyfactor_certificate_authority_unit_test.go, which also
// re-verifies the Interval/Daily-only cases this file used to own alone.
// ---------------------------------------------------------------------------

func caSchema(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceCertificateAuthorityType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}

// NOTE: TestUnitCAValidateConfigRejectsConflictingScheduleAttributes,
// TestUnitCAValidateConfigRejectsMalformedDailyTime,
// TestUnitCAValidateConfigAllowsEitherVariantAlone,
// TestUnitCAValidateConfigRejectsRFC3339DailyTime,
// TestUnitCAScheduleDailyTimeRoundTrip, and
// TestUnitCAScheduleDailyTimeNormalizesNonUTCOffset used to live here, but
// called buildSchedule/preserveCAUpdateFields with the pre-Weekly-variant
// 2-arg signatures those functions no longer have. Equivalent (and
// Weekly-extended) coverage for all of them now lives in
// resource_keyfactor_certificate_authority_unit_test.go.

// ---------------------------------------------------------------------------
// Regression tests for full-review round 2 finding #2 (correctness, medium):
//
// Go's time.Parse("15:04:05", ...) is lenient on hour width, so a
// single-digit-hour spelling like "7:00:00" parses successfully even though
// it isn't the canonical "HH:MM:SS" form the schema documents. ValidateConfig
// used to accept it, buildSchedule would send it, and Command would accept
// the API call -- but scheduleToState always formats the server's echoed
// Daily.Time with Format("15:04:05"), which zero-pads to "07:00:00". Nothing
// preserves the user's original non-canonical spelling (unlike key_retention,
// which has preserveKeyRetentionRepresentation for exactly this class of
// problem), so every apply of a non-zero-padded *_daily_time guaranteed
// "Provider produced inconsistent result after apply": planned "7:00:00" vs.
// applied "07:00:00", forever. The fix rejects non-canonical spellings in
// ValidateConfig, before plan/apply ever runs.
// ---------------------------------------------------------------------------

// TestUnitCAValidateConfigRejectsNonCanonicalDailyTime is the direct
// regression test: a *_daily_time value that time.Parse accepts but that
// isn't already zero-padded (a single-digit hour -- Go's reference-time
// parser is lenient on hour width only; minutes/seconds are always strict
// 2-digit, so "7:5:9"/"07:5:00" etc. are already caught by the pre-existing
// malformed-value check) must be rejected with an actionable diagnostic
// telling the user the canonical spelling to use, not silently accepted only
// to guarantee a permanent post-apply mismatch.
func TestUnitCAValidateConfigRejectsNonCanonicalDailyTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)
	r := resourceCertificateAuthority{}

	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"single-digit hour", "7:00:00", "07:00:00"},
		{"single-digit hour, non-zero minute/second", "9:30:15", "09:30:15"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := blankCAConfig()
			config.FullScanDailyTime = types.String{Value: tc.value}

			req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
			resp := &tfsdk.ValidateResourceConfigResponse{}
			r.ValidateConfig(ctx, req, resp)

			if !resp.Diagnostics.HasError() {
				t.Fatalf(
					"expected ValidateConfig to reject non-canonical full_scan_daily_time %q -- Command's API "+
						"would echo this back as %q on every read, guaranteeing \"Provider produced inconsistent "+
						"result after apply\" on every single apply, got no error",
					tc.value, tc.want,
				)
			}
			found := false
			for _, d := range resp.Diagnostics {
				if strings.Contains(d.Detail(), tc.want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf(
					"expected ValidateConfig's diagnostic to mention the canonical spelling %q so the user knows "+
						"how to fix it, got: %+v", tc.want, resp.Diagnostics,
				)
			}
		})
	}
}

// TestUnitCAValidateConfigAcceptsCanonicalDailyTime is the negative-space
// companion: an already-zero-padded "HH:MM:SS" value must NOT be rejected by
// the canonical-spelling check.
func TestUnitCAValidateConfigAcceptsCanonicalDailyTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)
	r := resourceCertificateAuthority{}

	config := blankCAConfig()
	config.FullScanDailyTime = types.String{Value: "07:00:00"}

	req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
	resp := &tfsdk.ValidateResourceConfigResponse{}
	r.ValidateConfig(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Errorf("expected no error for already-canonical full_scan_daily_time \"07:00:00\", got: %+v", resp.Diagnostics)
	}
}
