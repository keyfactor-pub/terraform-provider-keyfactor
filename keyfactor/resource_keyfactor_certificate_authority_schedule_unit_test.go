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
// TestUnitCAUpdatePreservesDailySchedule
// ---------------------------------------------------------------------------

// TestUnitCAUpdatePreservesDailySchedule is the regression test for
// preserveCAUpdateFields: an Update() whose config declares NEITHER variant
// of a schedule pair must preserve whichever variant prior state holds. This
// mirrors production behavior where UseStateForUnknown already carried the
// prior state's Daily value into plan before preserveCAUpdateFields runs;
// this test verifies preserveCAUpdateFields does not clobber that carried-
// forward value when config is genuinely silent on both attributes.
func TestUnitCAUpdatePreservesDailySchedule(t *testing.T) {
	t.Parallel()

	priorDaily := "15:46:00"

	// Simulates what the framework hands preserveCAUpdateFields: plan already
	// carries the prior state's Daily value forward via UseStateForUnknown,
	// because config declares neither full_scan_interval_minutes nor
	// full_scan_daily_time.
	plan := blankCAConfig()
	plan.FullScanDailyTime = types.String{Value: priorDaily}

	config := blankCAConfig()
	// config.FullScanIntervalMinutes and config.FullScanDailyTime both left Null
	// (blankCAConfig default) -- neither variant declared.

	preserveCAUpdateFields(&plan, config)

	if plan.FullScanDailyTime.Null || plan.FullScanDailyTime.Value != priorDaily {
		t.Fatalf(
			"FullScanDailyTime: want preserved value %q (config declares neither schedule variant), got Null=%v Value=%v -- "+
				"an undeclared update must not clear a real Daily schedule",
			priorDaily, plan.FullScanDailyTime.Null, plan.FullScanDailyTime.Value,
		)
	}
	if !plan.FullScanIntervalMinutes.Null {
		t.Errorf("FullScanIntervalMinutes: want Null (never set), got Value=%v", plan.FullScanIntervalMinutes.Value)
	}
}

// ---------------------------------------------------------------------------
// TestUnitCAUpdateScheduleVariantSwitchDoesNotResurrectOther
// ---------------------------------------------------------------------------

// TestUnitCAUpdateScheduleVariantSwitchDoesNotResurrectOther is the
// regression test for the variant-switch edge case preserveCAUpdateFields
// exists to handle: the user declares full_scan_daily_time for the first
// time (switching away from a prior Interval schedule) while leaving
// full_scan_interval_minutes undeclared. UseStateForUnknown independently
// carries the OLD full_scan_interval_minutes value forward from state, so
// without reconciliation the plan would have BOTH attributes non-null at
// once. preserveCAUpdateFields must null out the sibling that config did not
// declare.
func TestUnitCAUpdateScheduleVariantSwitchDoesNotResurrectOther(t *testing.T) {
	t.Parallel()

	newDaily := "03:00:00"

	// Plan as the framework would hand it to preserveCAUpdateFields: the newly
	// declared Daily value from config, PLUS the stale Interval value
	// UseStateForUnknown resurrected from state because
	// full_scan_interval_minutes itself is undeclared in config.
	plan := blankCAConfig()
	plan.FullScanDailyTime = types.String{Value: newDaily}
	plan.FullScanIntervalMinutes = types.Int64{Value: 60} // stale, from prior state

	config := blankCAConfig()
	config.FullScanDailyTime = types.String{Value: newDaily} // only this is actually declared

	preserveCAUpdateFields(&plan, config)

	if !plan.FullScanIntervalMinutes.Null {
		t.Fatalf(
			"FullScanIntervalMinutes: want Null (sibling of the newly-declared Daily variant must not be resurrected from state), got Value=%v -- "+
				"sending both would leave buildSchedule to arbitrarily pick one, and Read after apply would return only "+
				"the Daily-shaped schedule, nulling this value back out -- an inconsistent result after apply",
			plan.FullScanIntervalMinutes.Value,
		)
	}
	if plan.FullScanDailyTime.Null || plan.FullScanDailyTime.Value != newDaily {
		t.Errorf("FullScanDailyTime: want the newly-declared value %q preserved, got Null=%v Value=%v",
			newDaily, plan.FullScanDailyTime.Null, plan.FullScanDailyTime.Value)
	}

	// Symmetric case: switching FROM Daily TO Interval must null out the old
	// Daily value instead of leaving it to be resurrected.
	plan2 := blankCAConfig()
	plan2.IncrementalScanIntervalMinutes = types.Int64{Value: 30}
	plan2.IncrementalScanDailyTime = types.String{Value: "00:00:00"} // stale, from prior state

	config2 := blankCAConfig()
	config2.IncrementalScanIntervalMinutes = types.Int64{Value: 30} // only this is actually declared

	preserveCAUpdateFields(&plan2, config2)

	if !plan2.IncrementalScanDailyTime.Null {
		t.Fatalf(
			"IncrementalScanDailyTime: want Null (sibling of the newly-declared Interval variant must not be resurrected from state), got Value=%v",
			plan2.IncrementalScanDailyTime.Value,
		)
	}
	if plan2.IncrementalScanIntervalMinutes.Null || plan2.IncrementalScanIntervalMinutes.Value != 30 {
		t.Errorf("IncrementalScanIntervalMinutes: want the newly-declared value 30 preserved, got Null=%v Value=%v",
			plan2.IncrementalScanIntervalMinutes.Null, plan2.IncrementalScanIntervalMinutes.Value)
	}
}

// ---------------------------------------------------------------------------
// ValidateConfig regression tests
// ---------------------------------------------------------------------------

func caSchema(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceCertificateAuthorityType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}

// TestUnitCAValidateConfigRejectsConflictingScheduleAttributes is the
// regression test for ValidateConfig's mutual-exclusion check: declaring both
// full_scan_interval_minutes and full_scan_daily_time for the same schedule
// must be rejected at plan time rather than left for buildSchedule to
// arbitrarily resolve.
func TestUnitCAValidateConfigRejectsConflictingScheduleAttributes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig()
	config.FullScanIntervalMinutes = types.Int64{Value: 60}
	config.FullScanDailyTime = types.String{Value: "15:46:00"}

	r := resourceCertificateAuthority{}
	req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
	resp := &tfsdk.ValidateResourceConfigResponse{}
	r.ValidateConfig(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected ValidateConfig to reject full_scan_interval_minutes + full_scan_daily_time declared together, got no error")
	}
}

// TestUnitCAValidateConfigRejectsMalformedDailyTime is the regression test
// for ValidateConfig's RFC3339 parse check: a malformed *_daily_time value
// must be rejected at plan time with an actionable diagnostic rather than
// failing deep inside buildSchedule during Create/Update.
func TestUnitCAValidateConfigRejectsMalformedDailyTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig()
	config.FullScanDailyTime = types.String{Value: "not-a-timestamp"}

	r := resourceCertificateAuthority{}
	req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
	resp := &tfsdk.ValidateResourceConfigResponse{}
	r.ValidateConfig(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected ValidateConfig to reject a malformed full_scan_daily_time value, got no error")
	}
}

// TestUnitCAValidateConfigAllowsEitherVariantAlone is the negative-space
// regression test: ValidateConfig must NOT reject a config that declares
// exactly one variant of a schedule pair (the ordinary, valid case), whether
// that's the Interval or the Daily variant, and must not reject a config
// that declares no schedule at all.
func TestUnitCAValidateConfigAllowsEitherVariantAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)
	r := resourceCertificateAuthority{}

	t.Run("interval only", func(t *testing.T) {
		t.Parallel()
		config := blankCAConfig()
		config.FullScanIntervalMinutes = types.Int64{Value: 60}

		req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
		resp := &tfsdk.ValidateResourceConfigResponse{}
		r.ValidateConfig(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("expected no error for full_scan_interval_minutes declared alone, got: %+v", resp.Diagnostics)
		}
	})

	t.Run("daily only", func(t *testing.T) {
		t.Parallel()
		config := blankCAConfig()
		config.IncrementalScanDailyTime = types.String{Value: "15:46:00"}

		req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
		resp := &tfsdk.ValidateResourceConfigResponse{}
		r.ValidateConfig(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("expected no error for incremental_scan_daily_time declared alone, got: %+v", resp.Diagnostics)
		}
	})

	t.Run("neither declared", func(t *testing.T) {
		t.Parallel()
		config := blankCAConfig()

		req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
		resp := &tfsdk.ValidateResourceConfigResponse{}
		r.ValidateConfig(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("expected no error when no schedule variant is declared for any pair, got: %+v", resp.Diagnostics)
		}
	})
}

// ---------------------------------------------------------------------------
// Regression tests for GH issue #193 follow-up (dev-harness Gap A):
//
// Command normalizes a Daily schedule's Time field to the server's current
// date on every read while echoing back the exact UTC time-of-day it was
// given (confirmed live: PUT an explicit anchor date, re-GET). A full
// RFC3339 timestamp wire format can therefore never round-trip -- every
// Read would see a "changed" date component even though nothing about the
// schedule actually changed, and the RFC3339 offset was pure noise Command
// ignores entirely. This produced "Provider produced inconsistent result
// after apply" on every single apply once threshold_check_daily_time (etc)
// was declared with any date other than "today".
//
// The fix switches the wire format to a bare UTC time-of-day, "HH:MM:SS"
// (caDailyTimeLayout): scheduleToState formats with it, buildSchedule parses
// it and anchors the result to a fixed, arbitrary date (Command rewrites the
// date server-side regardless of what is sent), and ValidateConfig validates
// against the same layout -- rejecting the old RFC3339 format instead of
// silently accepting it.
// ---------------------------------------------------------------------------

// TestUnitCAValidateConfigRejectsRFC3339DailyTime guards against the old wire
// format regressing back in: a full RFC3339 timestamp (the pre-fix format)
// is NOT a valid caDailyTimeLayout ("HH:MM:SS") value and must be rejected,
// not silently accepted via a lenient parse.
func TestUnitCAValidateConfigRejectsRFC3339DailyTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	config := blankCAConfig()
	config.FullScanDailyTime = types.String{Value: "2026-07-17T15:46:00Z"}

	r := resourceCertificateAuthority{}
	req := tfsdk.ValidateResourceConfigRequest{Config: asConfig(t, ctx, schema, config)}
	resp := &tfsdk.ValidateResourceConfigResponse{}
	r.ValidateConfig(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatalf(
			"expected ValidateConfig to reject a full RFC3339 timestamp for full_scan_daily_time (the old, " +
				"pre-fix wire format is no longer accepted -- only a bare \"HH:MM:SS\" UTC time-of-day is), got no error",
		)
	}
}

// TestUnitCAScheduleDailyTimeRoundTrip is the round-trip regression test:
// buildSchedule must accept the bare "HH:MM:SS" UTC time-of-day format and
// scheduleToState must produce that exact same string back out, with no
// date component or timezone offset surviving anywhere in the round trip
// (Command's GET echoes the UTC time-of-day exactly but rewrites the anchor
// date to the current date, so any date information the provider sent or
// stored would be pure noise that could never round-trip cleanly).
func TestUnitCAScheduleDailyTimeRoundTrip(t *testing.T) {
	t.Parallel()

	sched, err := buildSchedule(types.Int64{Null: true}, types.String{Value: "07:00:00"})
	if err != nil {
		t.Fatalf("buildSchedule returned an error: %v", err)
	}
	if sched == nil || sched.Daily == nil {
		t.Fatalf("buildSchedule(\"07:00:00\") did not produce a Daily-shaped schedule: %+v", sched)
	}

	_, daily := scheduleToState(sched)
	if daily.Value != "07:00:00" {
		t.Errorf(
			"buildSchedule(\"07:00:00\") -> scheduleToState round-trip = %q, want \"07:00:00\" unchanged",
			daily.Value,
		)
	}
}

// TestUnitCAScheduleDailyTimeNormalizesNonUTCOffset verifies that a server
// response whose Daily.Time carries a non-UTC offset (e.g. if the SDK ever
// deserializes a "+02:00" wire value instead of normalizing to "Z" itself)
// is still normalized to the correct UTC time-of-day by scheduleToState,
// since scheduleToState explicitly calls .UTC() before formatting.
func TestUnitCAScheduleDailyTimeNormalizesNonUTCOffset(t *testing.T) {
	t.Parallel()

	loc := time.FixedZone("+02:00", 2*60*60)
	// 09:00 in +02:00 is 07:00 UTC.
	nonUTC := time.Date(2026, 7, 17, 9, 0, 0, 0, loc)
	sched := &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
		Daily: &v1.KeyfactorCommonSchedulingModelsTimeModel{Time: &nonUTC},
	}

	_, daily := scheduleToState(sched)

	if daily.Value != "07:00:00" {
		t.Errorf(
			"a Daily.Time carrying a non-UTC offset must normalize to the correct UTC time-of-day: got %q, want \"07:00:00\"",
			daily.Value,
		)
	}
}

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
