package keyfactor

import (
	"context"
	"testing"
	"time"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// caAllSchedulesNull has every schedule attribute explicitly Null, plus a
// properly-typed null allowed_requesters (a bare types.List{} zero-value has
// no ElemType set, which tfsdk.State/Plan.Set rejects). Tests that only care
// about a different attribute should copy this as their base state/config/
// plan value, since a Go zero-value types.Int64{}/types.String{} literal is a
// KNOWN empty value (Null: false, Value: 0/""), not Null -- left unset, it
// would spuriously look "declared" to declaredInConfig and, since
// buildSchedule now rejects Interval and Daily both being Known (see the
// F182-1 dual-known defense-in-depth check), a zero-value Int64{} (declared,
// "0") alongside a zero-value String{} (declared, "") for the same schedule
// would trip that error.
var caAllSchedulesNull = KeyfactorCertificateAuthority{
	FullScanIntervalMinutes:        types.Int64{Null: true},
	FullScanDailyTime:              types.String{Null: true},
	IncrementalScanIntervalMinutes: types.Int64{Null: true},
	IncrementalScanDailyTime:       types.String{Null: true},
	ThresholdCheckIntervalMinutes:  types.Int64{Null: true},
	ThresholdCheckDailyTime:        types.String{Null: true},
	AllowedRequesters:              types.List{Null: true, ElemType: types.StringType},
}

// TestUnitCAUpdatePreservesScanSchedules is a regression test for the bug where
// an Update() that did not declare the scan/threshold schedule attributes
// (undeclared in config) let buildCARequest omit FullScan/IncrementalScan/
// ThresholdCheck from the PUT body. Because Command's CA PUT is a full
// replacement, an omitted schedule is cleared server-side, silently wiping a
// live scan/threshold schedule on any unrelated Update. The fix preserves the
// prior state value when config does not declare the attribute.
func TestUnitCAUpdatePreservesScanSchedules(t *testing.T) {
	ctx := context.Background()

	// State carries a real scan/threshold schedule (as populated from a prior
	// Read of the server). Config leaves all three undeclared (Null); the raw
	// plan mirrors that (a real UseStateForUnknown-family modifier would have
	// already resolved it, but preserveCAUpdateFields must key on config, not
	// this incoming plan value, per its doc comment).
	state := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Value: 60},
		FullScanDailyTime:              types.String{Null: true},
		IncrementalScanIntervalMinutes: types.Int64{Value: 5},
		IncrementalScanDailyTime:       types.String{Null: true},
		ThresholdCheckIntervalMinutes:  types.Int64{Value: 30},
		ThresholdCheckDailyTime:        types.String{Null: true},
	}
	// Every schedule attribute config does not care about must be spelled out
	// explicitly as Null: a Go zero-value types.String{}/types.Int64{} literal is a
	// KNOWN empty value (Null: false), not Null, and would spuriously look
	// "declared" to declaredInConfig.
	config := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Null: true},
		FullScanDailyTime:              types.String{Null: true},
		IncrementalScanIntervalMinutes: types.Int64{Null: true},
		IncrementalScanDailyTime:       types.String{Null: true},
		ThresholdCheckIntervalMinutes:  types.Int64{Null: true},
		ThresholdCheckDailyTime:        types.String{Null: true},
	}
	plan := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Null: true},
		FullScanDailyTime:              types.String{Null: true},
		IncrementalScanIntervalMinutes: types.Int64{Null: true},
		IncrementalScanDailyTime:       types.String{Null: true},
		ThresholdCheckIntervalMinutes:  types.Int64{Null: true},
		ThresholdCheckDailyTime:        types.String{Null: true},
	}

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	if assert.NotNil(t, req.FullScan, "FullScan must be preserved, not omitted (omission clears it server-side)") {
		assert.NotNil(t, req.FullScan.Interval)
		assert.Equal(t, int32(60), *req.FullScan.Interval.Minutes)
	}
	if assert.NotNil(t, req.IncrementalScan, "IncrementalScan must be preserved") {
		assert.NotNil(t, req.IncrementalScan.Interval)
		assert.Equal(t, int32(5), *req.IncrementalScan.Interval.Minutes)
	}
	if assert.NotNil(t, req.ThresholdCheck, "ThresholdCheck must be preserved") {
		assert.NotNil(t, req.ThresholdCheck.Interval)
		assert.Equal(t, int32(30), *req.ThresholdCheck.Interval.Minutes)
	}
}

// TestUnitCAUpdatePreservesAllowedRequesters covers the allowed_requesters
// finding. Command's GET never returns the allowed-requester list, so it lives
// in state as a write-only field. On an unrelated Update() that leaves the
// attribute undeclared in config, buildCARequest previously omitted it, and
// because the CA PUT is a full replacement, the omission cleared the CA's
// real security-role list. The fix preserves the prior state value.
func TestUnitCAUpdatePreservesAllowedRequesters(t *testing.T) {
	ctx := context.Background()

	// Normal lifecycle: state carries the real requester list (preserved from
	// plan on Create/Read), config leaves it undeclared on an unrelated Update.
	state := caAllSchedulesNull
	state.AllowedRequesters = stringSliceToTfList([]string{"Role-A", "Role-B"})
	config := caAllSchedulesNull
	config.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}
	plan := caAllSchedulesNull
	plan.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	assert.Equal(t, []string{"Role-A", "Role-B"}, req.AllowedRequesters,
		"allowed_requesters must be preserved from state, not cleared, on an undeclared Update")
}

// TestUnitCAUpdatePostImportAllowedRequestersOmitted verifies the post-import
// edge: the server's GET does not return the list, so after ImportState the
// state value is Null and there is nothing to preserve. The request must OMIT
// allowed_requesters (nil slice) rather than send an explicit empty list, so
// Command leaves the existing list unchanged instead of being told to clear it.
func TestUnitCAUpdatePostImportAllowedRequestersOmitted(t *testing.T) {
	ctx := context.Background()

	// caResponseToState leaves allowed_requesters Null after an import.
	state := caAllSchedulesNull
	state.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}
	config := caAllSchedulesNull
	config.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}
	plan := caAllSchedulesNull
	plan.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	assert.Nil(t, req.AllowedRequesters,
		"allowed_requesters must be omitted (nil) when it was never populated, not sent as an explicit empty clear")
}

// TestUnitCAUpdatePreservesScanScheduleWhenPlanIsUnknownNotNull is a
// regression test distinguishing the config-keyed preserveCAUpdateFields from
// the old plan-Null-keyed version. The old check was `if p.Null { ... }`,
// which only catches the case where the incoming plan value is exactly Null
// — it does NOT catch a plan value that is Unknown (a distinct state from
// Null for types.Int64). buildCARequest treats Unknown identically to Null
// (both fail its `!Null && !Unknown` guard and get omitted from the PUT
// body), so an Unknown-but-undeclared plan value would have silently cleared
// the schedule under the old check.
//
// Keying on declaredInConfig(config.X) instead catches this case correctly:
// config is undeclared (Null) regardless of what shape the incoming plan
// value happens to be in, so the prior state value is preserved either way.
func TestUnitCAUpdatePreservesScanScheduleWhenPlanIsUnknownNotNull(t *testing.T) {
	ctx := context.Background()

	state := caAllSchedulesNull
	state.FullScanIntervalMinutes = types.Int64{Value: 60}
	config := caAllSchedulesNull // every schedule undeclared
	plan := caAllSchedulesNull
	plan.FullScanIntervalMinutes = types.Int64{Unknown: true} // NOT Null -- the case the old plan.Null check missed

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	assert.Equal(t, types.Int64{Value: 60}, plan.FullScanIntervalMinutes,
		"an undeclared-in-config schedule must be preserved from state even when the incoming plan value is Unknown rather than Null")
	if assert.NotNil(t, req.FullScan, "FullScan must be preserved, not omitted (omission clears it server-side)") {
		assert.NotNil(t, req.FullScan.Interval)
		assert.Equal(t, int32(60), *req.FullScan.Interval.Minutes)
	}
}

// TestUnitCAReadSurfacesAllowedRequestersDrift is the regression test for G3:
// preserveSecrets used to echo the prior state/plan's allowed_requesters over
// whatever caResponseToState had just mapped from the server's GET response,
// even though Command v25.5+ genuinely returns the list (confirmed live).
// That meant Read() could never detect a role added/removed from the
// allowed-requester list out-of-band -- it always silently "corrected" the
// server's real value back to the stale one already in state.
//
// This builds a server response reporting a DIFFERENT allowed-requester list
// than prior state/plan carries, runs it through caResponseToState then
// preserveSecrets (mirroring the Read()/Create()/Update() call sequence), and
// asserts the server's list wins -- not the stale echo.
func TestUnitCAReadSurfacesAllowedRequestersDrift(t *testing.T) {
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(9)
	resp.SetLogicalName("Standalone-CA")
	resp.SetHostName("http://ca.lab/ejbca")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType
	resp.AllowedRequesters = []string{"Role-C"} // server truth, changed out-of-band

	staleSource := KeyfactorCertificateAuthority{
		AllowedRequesters: stringSliceToTfList([]string{"Role-A", "Role-B"}), // what Terraform last knew
	}

	newState := caResponseToState(resp)
	preserveSecrets(&newState, staleSource)

	var got []string
	for _, e := range newState.AllowedRequesters.Elems {
		if sv, ok := e.(types.String); ok {
			got = append(got, sv.Value)
		}
	}

	assert.Equal(t, []string{"Role-C"}, got,
		"Read must surface the server's real allowed_requesters, not silently re-echo a stale prior value")
}

// TestUnitCAUpdateExplicitEmptyAllowedRequestersIsSent is the companion
// regression test for the clear path: with the config-keyed
// preserveCAUpdateFields, an explicitly-declared empty list ([]) in config is
// NOT undeclared (declaredInConfig treats a non-null, even empty, list as
// declared), so it must be sent through to buildCARequest as a real clearing
// value rather than being preserved from the old (non-empty) state.
func TestUnitCAUpdateExplicitEmptyAllowedRequestersIsSent(t *testing.T) {
	ctx := context.Background()

	state := caAllSchedulesNull
	state.AllowedRequesters = stringSliceToTfList([]string{"Role-A", "Role-B"})
	// An explicit [] in config: Null=false, Elems empty -- declared, not omitted.
	explicitEmpty := types.List{ElemType: types.StringType, Elems: []attr.Value{}}
	config := caAllSchedulesNull
	config.AllowedRequesters = explicitEmpty
	plan := caAllSchedulesNull
	plan.AllowedRequesters = explicitEmpty

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	assert.NotNil(t, req.AllowedRequesters, "an explicitly declared empty list must be sent through, not preserved from the old state")
	assert.Len(t, req.AllowedRequesters, 0, "the cleared list must be sent as an explicit empty list, not the old requesters")
}

// TestUnitCAReadPreservesDailySchedule is a regression test for the bug where
// caResponseToState only recognized the Interval variant of a Command schedule.
// A CA whose FullScan/IncrementalScan/ThresholdCheck is Daily-shaped (Command's
// KeyfactorSchedule model supports Interval, Daily, Weekly, Monthly, ExactlyOnce,
// and Immediate as mutually exclusive variants) fell into the same "no schedule
// at all" Null branch as an actually-unconfigured schedule, because there was no
// schema attribute to hold the Daily value. Verified live against a real CA
// (int25-4-1.kftestlab.com, CA id 1) whose real FullScan.Daily.Time schedule was
// silently wiped by an Update that never touched schedule config.
func TestUnitCAReadPreservesDailySchedule(t *testing.T) {
	dailyTime := time.Date(2026, 7, 17, 15, 46, 0, 0, time.UTC)
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{
		FullScan: &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Daily: &v1.KeyfactorCommonSchedulingModelsTimeModel{Time: &dailyTime},
		},
		// IncrementalScan/ThresholdCheck left nil: genuinely unconfigured, must
		// stay Null on both variants (i.e. Daily support must not manufacture a
		// value where none exists).
	}

	state := caResponseToState(resp)

	assert.True(t, state.FullScanIntervalMinutes.Null,
		"a Daily-shaped schedule must not populate the Interval attribute")
	if assert.False(t, state.FullScanDailyTime.Null,
		"a Daily-shaped schedule must be captured into full_scan_daily_time, not collapsed to Null (Null is indistinguishable from no schedule at all)") {
		assert.Equal(t, "15:46:00", state.FullScanDailyTime.Value)
	}

	assert.True(t, state.IncrementalScanIntervalMinutes.Null)
	assert.True(t, state.IncrementalScanDailyTime.Null)
	assert.True(t, state.ThresholdCheckIntervalMinutes.Null)
	assert.True(t, state.ThresholdCheckDailyTime.Null)
}

// TestUnitCAUpdatePreservesDailySchedule is the Update-path half of the Daily
// schedule regression: a Daily-shaped schedule captured into prior state (via the
// fixed caResponseToState) must be resent on an Update that leaves the schedule
// undeclared in config, exactly like the existing Interval preservation behavior.
// Before the fix, a Daily schedule could never even reach state as non-Null (see
// TestUnitCAReadPreservesDailySchedule), so preserveCAUpdateFields had nothing to
// preserve and buildCARequest always omitted FullScan — which Command's
// full-replace PUT semantics interpret as "clear it".
func TestUnitCAUpdatePreservesDailySchedule(t *testing.T) {
	ctx := context.Background()

	state := caAllSchedulesNull
	state.FullScanDailyTime = types.String{Value: "15:46:00"}
	config := caAllSchedulesNull // every schedule undeclared
	plan := caAllSchedulesNull

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	if assert.NotNil(t, req.FullScan, "a Daily schedule must be preserved, not omitted (omission clears it server-side)") {
		assert.Nil(t, req.FullScan.Interval, "a preserved Daily schedule must not also set Interval")
		if assert.NotNil(t, req.FullScan.Daily) {
			assert.NotNil(t, req.FullScan.Daily.Time)
			assert.Equal(t, "15:46:00", req.FullScan.Daily.Time.UTC().Format(caDailyTimeLayout))
		}
	}
}

// TestUnitCAUpdateScheduleVariantSwitchDoesNotResurrectOther verifies that when a
// config-declared change switches a schedule from Daily to Interval (or vice
// versa), preserveCAUpdateFields does not resurrect the OTHER variant from prior
// state alongside the newly-declared one. Command's schedule is a tagged union;
// sending both Interval and Daily on the same PUT would be invalid.
func TestUnitCAUpdateScheduleVariantSwitchDoesNotResurrectOther(t *testing.T) {
	ctx := context.Background()

	// Prior state: Daily. Plan: user has now declared an Interval, switching the
	// variant entirely.
	state := caAllSchedulesNull
	state.FullScanDailyTime = types.String{Value: "15:46:00"}
	// config declares the new Interval value directly -- this is the switch.
	config := caAllSchedulesNull
	config.FullScanIntervalMinutes = types.Int64{Value: 60}
	plan := caAllSchedulesNull
	plan.FullScanIntervalMinutes = types.Int64{Value: 60}

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	if assert.NotNil(t, req.FullScan) {
		assert.Nil(t, req.FullScan.Daily,
			"switching to Interval must not resurrect the old Daily value from prior state")
		if assert.NotNil(t, req.FullScan.Interval) {
			assert.Equal(t, int32(60), *req.FullScan.Interval.Minutes)
		}
	}
}

// TestUnitCAValidateConfigRejectsConflictingScheduleAttributes verifies the
// plan-time guard added alongside the Daily schedule support: declaring both
// *_interval_minutes and *_daily_time for the same schedule is invalid (Command's
// schedule is a tagged union, never both at once) and must be rejected before
// Create/Update ever runs, rather than silently preferring one.
func TestUnitCAValidateConfigRejectsConflictingScheduleAttributes(t *testing.T) {
	cfg := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes: types.Int64{Value: 60},
		FullScanDailyTime:       types.String{Value: "15:46:00"},
	}

	diags := validateCAScheduleAttributes(cfg)

	assert.True(t, diags.HasError(),
		"setting both full_scan_interval_minutes and full_scan_daily_time must be a plan-time error")
}

// TestUnitCAValidateConfigRejectsMalformedDailyTime verifies that a non-"HH:MM:SS"
// *_daily_time value is rejected at plan time, since buildSchedule/time.Parse
// assumes a valid caDailyTimeLayout string by the time it runs on the Create/Update
// path.
func TestUnitCAValidateConfigRejectsMalformedDailyTime(t *testing.T) {
	cfg := KeyfactorCertificateAuthority{
		FullScanDailyTime: types.String{Value: "not-a-timestamp"},
	}

	diags := validateCAScheduleAttributes(cfg)

	assert.True(t, diags.HasError(), "a non-\"HH:MM:SS\" full_scan_daily_time must be a plan-time error")
}

// TestUnitCAValidateConfigRejectsRFC3339DailyTime guards against the old wire
// format regressing back in: a full RFC3339 timestamp (the pre-F182-2 format) is
// NOT a valid caDailyTimeLayout ("HH:MM:SS") value and must be rejected, not
// silently accepted via a lenient parse.
func TestUnitCAValidateConfigRejectsRFC3339DailyTime(t *testing.T) {
	cfg := KeyfactorCertificateAuthority{
		FullScanDailyTime: types.String{Value: "2026-07-17T15:46:00Z"},
	}

	diags := validateCAScheduleAttributes(cfg)

	assert.True(t, diags.HasError(), "a full RFC3339 timestamp is no longer the accepted full_scan_daily_time format")
}

// TestUnitCAValidateConfigAllowsEitherVariantAlone confirms the common,
// non-error cases: a schedule declared as Interval only, Daily only, or entirely
// undeclared must all pass validation cleanly.
func TestUnitCAValidateConfigAllowsEitherVariantAlone(t *testing.T) {
	// allNull is the baseline: every schedule attribute explicitly Null (as a real
	// plan/config would represent "undeclared"). Go zero-value struct literals
	// default types.String/types.Int64 to a KNOWN empty value (Null: false), not
	// Null, so every attribute this sub-test does not care about must be spelled
	// out explicitly or it will spuriously look "declared" to validateCAScheduleAttributes.
	allNull := KeyfactorCertificateAuthority{
		FullScanIntervalMinutes:        types.Int64{Null: true},
		FullScanDailyTime:              types.String{Null: true},
		IncrementalScanIntervalMinutes: types.Int64{Null: true},
		IncrementalScanDailyTime:       types.String{Null: true},
		ThresholdCheckIntervalMinutes:  types.Int64{Null: true},
		ThresholdCheckDailyTime:        types.String{Null: true},
	}

	intervalOnly := allNull
	intervalOnly.FullScanIntervalMinutes = types.Int64{Value: 60}
	assert.False(t, validateCAScheduleAttributes(intervalOnly).HasError())

	dailyOnly := allNull
	dailyOnly.FullScanDailyTime = types.String{Value: "15:46:00"}
	assert.False(t, validateCAScheduleAttributes(dailyOnly).HasError())

	assert.False(t, validateCAScheduleAttributes(allNull).HasError())
}

// TestUnitCAScheduleDailyTimeRoundTrip is the round-trip regression test for
// F182-2: buildSchedule must accept the bare "HH:MM:SS" UTC time-of-day format and
// scheduleToState must produce that exact same string back out, with no date
// component or timezone offset surviving anywhere in the round trip (Command's GET
// echoes the UTC time-of-day exactly but rewrites the anchor date to the current
// date, so any date information the provider sent or stored would be pure noise
// that could never round-trip cleanly).
func TestUnitCAScheduleDailyTimeRoundTrip(t *testing.T) {
	sched, err := buildSchedule(types.Int64{Null: true}, types.String{Value: "07:00:00"})
	if assert.NoError(t, err) && assert.NotNil(t, sched) && assert.NotNil(t, sched.Daily) {
		_, daily := scheduleToState(sched)
		assert.Equal(t, "07:00:00", daily.Value,
			"buildSchedule(\"07:00:00\") -> scheduleToState must round-trip to the same HH:MM:SS string")
	}
}

// TestUnitCAScheduleDailyTimeNormalizesNonUTCOffset verifies that a server
// response whose Daily.Time carries a non-UTC offset (e.g. if the SDK ever
// deserializes a "+02:00" wire value instead of normalizing to "Z" itself) is
// still normalized to the correct UTC time-of-day by scheduleToState, since
// scheduleToState explicitly calls .UTC() before formatting.
func TestUnitCAScheduleDailyTimeNormalizesNonUTCOffset(t *testing.T) {
	loc := time.FixedZone("+02:00", 2*60*60)
	// 09:00 in +02:00 is 07:00 UTC.
	nonUTC := time.Date(2026, 7, 17, 9, 0, 0, 0, loc)
	sched := &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
		Daily: &v1.KeyfactorCommonSchedulingModelsTimeModel{Time: &nonUTC},
	}

	_, daily := scheduleToState(sched)

	assert.Equal(t, "07:00:00", daily.Value,
		"a Daily.Time carrying a non-UTC offset must be normalized to the correct UTC time-of-day")
}

// TestUnitCAReadKeepsScheduleSentinel is the red/green regression test for
// G2's Read-path sentinel stability: when the server reports no schedule at
// all (FullScan nil) and the prior state held the declared clear sentinel
// (full_scan_interval_minutes = 0), Read must write that same sentinel back
// into state, not the server's bare Null -- otherwise a config that still
// declares 0 would see a spurious null diff on every subsequent plan.
func TestUnitCAReadKeepsScheduleSentinel(t *testing.T) {
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(45)
	resp.SetLogicalName("tf-unit-ca-read-sentinel")
	resp.SetHostName("ca.lab.example.com")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType
	// FullScan left nil: the server has no schedule (Command actually cleared
	// it, per the declared sentinel on a prior apply).

	priorState := caAllSchedulesNull
	priorState.FullScanIntervalMinutes = types.Int64{Value: 0}

	newState := caResponseToState(resp)
	keepScheduleSentinels(context.Background(), &newState, priorState)

	if assert.False(t, newState.FullScanIntervalMinutes.Null,
		"a prior sentinel must be carried forward, not surfaced as the server's bare Null") {
		assert.Equal(t, int64(0), newState.FullScanIntervalMinutes.Value)
	}
	assert.True(t, newState.FullScanDailyTime.Null)
}

// TestUnitCAReadSurfacesDriftOverSentinel is the companion case: when the
// server reports a REAL schedule (e.g. an out-of-band re-add of the interval
// Command's UI or another tool performed directly), Read must surface that
// real value as genuine drift, never mask it behind a stale sentinel from
// prior state.
func TestUnitCAReadSurfacesDriftOverSentinel(t *testing.T) {
	minutes := int32(30)
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{
		FullScan: &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Interval: &v1.KeyfactorCommonSchedulingModelsIntervalModel{Minutes: &minutes},
		},
	}
	resp.SetId(46)
	resp.SetLogicalName("tf-unit-ca-read-sentinel-drift")
	resp.SetHostName("ca.lab.example.com")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType

	priorState := caAllSchedulesNull
	priorState.FullScanIntervalMinutes = types.Int64{Value: 0} // the prior declared sentinel

	newState := caResponseToState(resp)
	keepScheduleSentinels(context.Background(), &newState, priorState)

	if assert.False(t, newState.FullScanIntervalMinutes.Null,
		"the server's real out-of-band schedule must be surfaced, not left Null") {
		assert.Equal(t, int64(30), newState.FullScanIntervalMinutes.Value,
			"real server drift (0 -> 30) must win over the stale prior sentinel")
	}
}

// ---------------------------------------------------------------------------
// F1: properties JSON-normalization plan modifier
// ---------------------------------------------------------------------------

// TestUnitCANormalizePropertiesJSON verifies the helper (previously dead
// code, never wired into a plan modifier) treats differently-formatted but
// semantically-equal JSON as equal, and falls back to the raw string for
// unparseable input.
func TestUnitCANormalizePropertiesJSON(t *testing.T) {
	assert.Equal(t,
		normalizePropertiesJSON(`{"a":1,"b":2}`),
		normalizePropertiesJSON(`{"b": 2, "a": 1}`),
		"key order and whitespace must not affect the normalized form",
	)
	assert.Equal(t, "", normalizePropertiesJSON(""), "empty string normalizes to empty string")
	assert.Equal(t, "not-json", normalizePropertiesJSON("not-json"), "unparseable input falls back to the raw string unchanged")
}

// TestUnitCAPropertiesModifierSuppressesReorderedJSONDiff is the red/green
// regression test for F1: normalizePropertiesJSON was defined but never
// wired into a plan modifier, so with the prior schema (a bare
// tfsdk.UseStateForUnknown()) a config-declared properties value already
// plans as Known -- UseStateForUnknown only ever intervenes on an Unknown
// plan, so it does nothing here, leaving the plan at the config's literal
// text. If Command's GET re-serializes the same JSON with different key
// order/whitespace than what's in state, the plan (config text) and state
// (server's differently-formatted text) differ byte-for-byte -- a permanent
// diff even though the value is semantically unchanged. This test fails
// against the un-fixed schema (verified by temporarily swapping the
// "properties" PlanModifiers back to []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()}
// during development: resp.AttributePlan stayed at the config's text,
// `{"a":1,"b":2}` != state's `{"b":2,"a":1}`) and passes once
// normalizedJSONPropertiesModifier is wired in, since it resets the plan to
// state's exact text when the two are semantically equal.
func TestUnitCAPropertiesModifierSuppressesReorderedJSONDiff(t *testing.T) {
	state := types.String{Value: `{"b":2,"a":1}`}
	plan := types.String{Value: `{"a":1,"b":2}`} // same data, different key order -- config-declared

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState: state,
		AttributePlan:  plan,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.String, got %T", resp.AttributePlan) {
		assert.Equal(t, state.Value, got.Value,
			"a plan that is semantically equal to state (differing only in JSON key order/whitespace) must be reset to state's exact text, suppressing the diff")
	}
}

// TestUnitCAPropertiesModifierSurfacesRealChange is the companion case: a
// genuinely different properties value (not just reformatted) must still
// plan as a real diff, never be suppressed by the normalization.
func TestUnitCAPropertiesModifierSurfacesRealChange(t *testing.T) {
	state := types.String{Value: `{"a":1}`}
	plan := types.String{Value: `{"a":2}`}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState: state,
		AttributePlan:  plan,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok) {
		assert.Equal(t, plan.Value, got.Value, "a genuine value change must not be suppressed")
	}
}

// TestUnitCABarePropertiesUseStateForUnknownDoesNotSuppressReorderedJSONDiff
// is the concrete "red" reproduction for F1, run against the schema's actual
// PRE-FIX plan modifier (tfsdk.UseStateForUnknownModifier{}, what "properties"
// used before this change) rather than against a hand-edited schema: given
// the exact same config-declared-but-reordered-JSON scenario as
// TestUnitCAPropertiesModifierSuppressesReorderedJSONDiff, the bare modifier
// leaves the plan at the config's literal text because the plan is already
// Known (config declared it) -- UseStateForUnknown only ever intervenes on an
// Unknown plan. That mismatched plan-vs-state text is exactly the perpetual
// diff this bug reports. normalizedJSONPropertiesModifier (tested above)
// fixes it by resetting the plan to state's text when the two are
// semantically equal.
func TestUnitCABarePropertiesUseStateForUnknownDoesNotSuppressReorderedJSONDiff(t *testing.T) {
	state := types.String{Value: `{"b":2,"a":1}`}
	plan := types.String{Value: `{"a":1,"b":2}`} // same data, different key order -- config-declared

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  state,
		AttributeConfig: plan,
		AttributePlan:   plan,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	tfsdk.UseStateForUnknownModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.String, got %T", resp.AttributePlan) {
		assert.NotEqual(t, state.Value, got.Value,
			"reproduces the bug: the pre-fix bare UseStateForUnknown modifier does NOT suppress a reordered-JSON diff, leaving the plan at the config's differently-formatted text")
		assert.Equal(t, plan.Value, got.Value)
	}
}

// TestUnitCAPropertiesModifierUndeclaredCopiesState covers the Computed-only
// case (properties left undeclared in config): the plan starts Unknown, and
// the modifier must copy state forward, matching plain UseStateForUnknown
// semantics.
func TestUnitCAPropertiesModifierUndeclaredCopiesState(t *testing.T) {
	state := types.String{Value: `{"a":1}`}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState: state,
		AttributePlan:  types.String{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok) {
		assert.Equal(t, state.Value, got.Value)
		assert.False(t, got.Unknown)
	}
}

// TestUnitCAPropertiesModifierCreateStaysUnknown is the Create-time
// companion: with no prior state to copy from (AttributeState itself
// Unknown), the plan must be left Unknown rather than fabricating a value.
func TestUnitCAPropertiesModifierCreateStaysUnknown(t *testing.T) {
	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState: types.String{Unknown: true},
		AttributePlan:  types.String{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok) {
		assert.True(t, got.Unknown, "no prior state to copy from on Create -- plan must stay Unknown")
	}
}

// ---------------------------------------------------------------------------
// F3/F4: ValidateConfig constraint enforcement
// ---------------------------------------------------------------------------

// caConstraintsAllUnset has every attribute validateCAConfigConstraints
// looks at explicitly Null. As with caAllSchedulesNull above, a Go zero-value
// types.Bool{}/types.Int64{}/types.List{} literal is a KNOWN empty/false/zero
// value (Null: false), not Null -- left unset, EnforceUniqueDN/Standalone
// would spuriously look "declared false" and AllowedEnrollmentTypes/
// UseAllowedRequesters would spuriously look "declared 0/false", tripping the
// very checks these tests don't intend to exercise. Tests that only care
// about a subset of these attributes should copy this baseline and override
// just the ones under test.
var caConstraintsAllUnset = KeyfactorCertificateAuthority{
	EnforceUniqueDN:               types.Bool{Null: true},
	NewEndEntityOnRenewAndReissue: types.Bool{Null: true},
	CAType:                        types.Int64{Null: true},
	Standalone:                    types.Bool{Null: true},
	AllowedEnrollmentTypes:        types.Int64{Null: true},
	UseAllowedRequesters:          types.Bool{Null: true},
	AllowedRequesters:             types.List{Null: true, ElemType: types.StringType},
}

// TestUnitCAValidateConfigRejectsEnforceUniqueDNWithNewEndEntity is the F3
// regression: enforce_unique_dn and new_end_entity_on_renew_and_reissue are
// documented as mutually exclusive but, before this fix, nothing enforced
// it -- both could be set to true with no plan-time error.
func TestUnitCAValidateConfigRejectsEnforceUniqueDNWithNewEndEntity(t *testing.T) {
	cfg := caConstraintsAllUnset
	cfg.EnforceUniqueDN = types.Bool{Value: true}
	cfg.NewEndEntityOnRenewAndReissue = types.Bool{Value: true}

	diags := validateCAConfigConstraints(cfg)

	assert.True(t, diags.HasError(), "enforce_unique_dn and new_end_entity_on_renew_and_reissue both true must be a plan-time error")
}

// TestUnitCAValidateConfigAllowsEnforceUniqueDNOrNewEndEntityAlone confirms
// the non-error cases for the F3 pair: either attribute alone, or neither
// declared, must all pass cleanly.
func TestUnitCAValidateConfigAllowsEnforceUniqueDNOrNewEndEntityAlone(t *testing.T) {
	dnOnly := caConstraintsAllUnset
	dnOnly.EnforceUniqueDN = types.Bool{Value: true}
	assert.False(t, validateCAConfigConstraints(dnOnly).HasError())

	newEntityOnly := caConstraintsAllUnset
	newEntityOnly.NewEndEntityOnRenewAndReissue = types.Bool{Value: true}
	assert.False(t, validateCAConfigConstraints(newEntityOnly).HasError())

	assert.False(t, validateCAConfigConstraints(caConstraintsAllUnset).HasError())
}

// TestUnitCAValidateConfigRejectsNewEndEntityFalseForHTTPSCa is the F4
// regression: new_end_entity_on_renew_and_reissue is documented as required
// true for HTTPS CAs (ca_type=1) but, before this fix, an explicit false was
// silently accepted at plan time for an HTTPS CA.
func TestUnitCAValidateConfigRejectsNewEndEntityFalseForHTTPSCa(t *testing.T) {
	cfg := caConstraintsAllUnset
	cfg.CAType = types.Int64{Value: caHTTPSType}
	cfg.NewEndEntityOnRenewAndReissue = types.Bool{Value: false}

	diags := validateCAConfigConstraints(cfg)

	assert.True(t, diags.HasError(), "new_end_entity_on_renew_and_reissue=false with ca_type=1 (HTTPS) must be a plan-time error")
}

// TestUnitCAValidateConfigAllowsNewEndEntityUnsetOrUnknownForHTTPSCa confirms
// that config-time validation never fabricates a requirement on an attribute
// the practitioner didn't declare, or on a ca_type that isn't resolvable yet
// -- only an explicitly configured, known violation is rejected.
func TestUnitCAValidateConfigAllowsNewEndEntityUnsetOrUnknownForHTTPSCa(t *testing.T) {
	undeclared := caConstraintsAllUnset
	undeclared.CAType = types.Int64{Value: caHTTPSType}
	assert.False(t, validateCAConfigConstraints(undeclared).HasError(),
		"new_end_entity_on_renew_and_reissue left undeclared must never error, even for an HTTPS CA")

	unknownCAType := caConstraintsAllUnset
	unknownCAType.CAType = types.Int64{Unknown: true}
	unknownCAType.NewEndEntityOnRenewAndReissue = types.Bool{Value: false}
	assert.False(t, validateCAConfigConstraints(unknownCAType).HasError(),
		"an unknown ca_type (e.g. referencing another resource's not-yet-known output) must never error")

	trueForHTTPS := caConstraintsAllUnset
	trueForHTTPS.CAType = types.Int64{Value: caHTTPSType}
	trueForHTTPS.NewEndEntityOnRenewAndReissue = types.Bool{Value: true}
	assert.False(t, validateCAConfigConstraints(trueForHTTPS).HasError())
}

// TestUnitCAValidateConfigRejectsStandaloneOnlyAttributesWithStandaloneFalse
// is the F4 regression for allowed_enrollment_types/use_allowed_requesters/
// allowed_requesters: each is documented as applying to standalone CAs only,
// but before this fix none of them were rejected when standalone was
// explicitly declared false.
func TestUnitCAValidateConfigRejectsStandaloneOnlyAttributesWithStandaloneFalse(t *testing.T) {
	base := func() KeyfactorCertificateAuthority {
		cfg := caConstraintsAllUnset
		cfg.Standalone = types.Bool{Value: false}
		return cfg
	}

	allowedEnrollmentTypes := base()
	allowedEnrollmentTypes.AllowedEnrollmentTypes = types.Int64{Value: 2}
	assert.True(t, validateCAConfigConstraints(allowedEnrollmentTypes).HasError(),
		"allowed_enrollment_types requires standalone=true")

	useAllowedRequesters := base()
	useAllowedRequesters.UseAllowedRequesters = types.Bool{Value: true}
	assert.True(t, validateCAConfigConstraints(useAllowedRequesters).HasError(),
		"use_allowed_requesters applies to standalone CAs only")

	allowedRequesters := base()
	allowedRequesters.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.True(t, validateCAConfigConstraints(allowedRequesters).HasError(),
		"allowed_requesters applies to standalone CAs only")
}

// TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneUnsetOrUnknown
// confirms that config-time validation can't resolve a computed/unresolved
// standalone value, so leaving it undeclared or Unknown must never trip
// these checks regardless of what the standalone-only attributes are set to.
func TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneUnsetOrUnknown(t *testing.T) {
	undeclared := caConstraintsAllUnset
	undeclared.AllowedEnrollmentTypes = types.Int64{Value: 2}
	undeclared.UseAllowedRequesters = types.Bool{Value: true}
	undeclared.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.False(t, validateCAConfigConstraints(undeclared).HasError(),
		"standalone left undeclared must never error -- config-time validation can't resolve a computed standalone value")

	unknown := undeclared
	unknown.Standalone = types.Bool{Unknown: true}
	assert.False(t, validateCAConfigConstraints(unknown).HasError(),
		"an unknown standalone (e.g. referencing another resource's not-yet-known output) must never error")
}

// TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneTrue is
// the passing case for a real standalone CA: all three standalone-only
// attributes together must remain legal.
func TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneTrue(t *testing.T) {
	cfg := caConstraintsAllUnset
	cfg.Standalone = types.Bool{Value: true}
	cfg.AllowedEnrollmentTypes = types.Int64{Value: 2}
	cfg.UseAllowedRequesters = types.Bool{Value: true}
	cfg.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.False(t, validateCAConfigConstraints(cfg).HasError())
}

// ---------------------------------------------------------------------------
// F9: auth certificate metadata else-null branch
// ---------------------------------------------------------------------------

// TestUnitCAReadAuthCertificateMetadataNullWhenAbsent is the red/green
// regression test for F9: caResponseToState only set
// auth_certificate_issued_dn/auth_certificate_issuer_dn/
// auth_certificate_thumbprint inside "if resp.AuthCertificate != nil", so a
// CA with no auth certificate configured left those three fields at the Go
// zero-value types.String{} -- a KNOWN empty string, not Null -- instead of
// explicit Null like every other pointer field in this function
// (boolPtrToTfBool/nullableStringToTfString/etc. all return Null on a nil
// pointer). Before the fix, the assertions below fail because
// newState.AuthCertificateIssuedDN.Null is false (Value == "").
func TestUnitCAReadAuthCertificateMetadataNullWhenAbsent(t *testing.T) {
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(47)
	resp.SetLogicalName("tf-unit-ca-no-auth-cert")
	resp.SetHostName("ca.lab.example.com")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType
	// resp.AuthCertificate intentionally left nil: no auth certificate configured.

	newState := caResponseToState(resp)

	assert.True(t, newState.AuthCertificateIssuedDN.Null,
		"auth_certificate_issued_dn must be Null (not a known empty string) when the CA has no auth certificate")
	assert.True(t, newState.AuthCertificateIssuerDN.Null,
		"auth_certificate_issuer_dn must be Null (not a known empty string) when the CA has no auth certificate")
	assert.True(t, newState.AuthCertificateThumbprint.Null,
		"auth_certificate_thumbprint must be Null (not a known empty string) when the CA has no auth certificate")
}
