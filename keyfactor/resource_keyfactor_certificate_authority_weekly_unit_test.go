package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitCAWeeklyScheduleDayNameStringsDeserialize is the red/green
// regression test for keyfactor-pub/terraform-provider-keyfactor#185: Command
// v25.5 sends a Weekly schedule's Days as day-NAME strings (e.g. "Monday"),
// not the small integers the original generated SDK model exclusively
// accepted. Before keyfactor-go-client-sdk v24.1.2-rc.0,
// v1.SystemDayOfWeek.UnmarshalJSON only tried json.Unmarshal into an int32
// and returned an error for a JSON string -- so a real GET
// /CertificateAuthority response carrying a Weekly schedule would fail to
// deserialize entirely (the SDK call itself would error), and this
// provider's Read would surface that raw deserialization failure instead of
// ever reaching scheduleToState/caResponseToState. This test exercises the
// exact JSON shape Command sends (confirmed live) end-to-end: raw bytes ->
// SDK unmarshal -> caResponseToState -> the new *_weekly_days/*_weekly_time
// state attributes. Before the SDK bump this test's json.Unmarshal call
// itself failed with "... is not a valid SystemDayOfWeek" (day names are not
// valid int32 JSON); with keyfactor-go-client-sdk v24.1.2-rc.0 vendored, the
// string fallback in SystemDayOfWeek.UnmarshalJSON lets it succeed.
func TestUnitCAWeeklyScheduleDayNameStringsDeserialize(t *testing.T) {
	const body = `{
		"Id": 100,
		"LogicalName": "tf-unit-ca-weekly-string-days",
		"HostName": "ca.lab.example.com",
		"CAType": 1,
		"FullScan": {"Weekly": {"Days": ["Friday", "Monday"], "Time": "2026-07-17T07:00:00Z"}}
	}`

	var resp v1.CertificateAuthoritiesCertificateAuthorityResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("SDK failed to deserialize a Weekly schedule with day-name strings (pre-v24.1.2-rc.0, issue #185): %s", err)
	}

	state := caResponseToState(&resp)

	assert.True(t, state.FullScanIntervalMinutes.Null, "a Weekly-shaped schedule must not populate the Interval attribute")
	assert.True(t, state.FullScanDailyTime.Null, "a Weekly-shaped schedule must not populate the Daily attribute")
	if assert.False(t, state.FullScanWeeklyDays.Null, "a Weekly-shaped schedule must populate full_scan_weekly_days, not collapse to Null") {
		var days []string
		diags := state.FullScanWeeklyDays.ElementsAs(context.Background(), &days, false)
		assert.False(t, diags.HasError())
		assert.Equal(t, []string{"Monday", "Friday"}, days,
			"days must come back sorted by enum value (Monday=1, Friday=5), not the wire order [\"Friday\", \"Monday\"]")
	}
	if assert.False(t, state.FullScanWeeklyTime.Null) {
		assert.Equal(t, "07:00:00", state.FullScanWeeklyTime.Value)
	}
}

// TestUnitCAWeeklyScheduleRoundTrip is the round-trip regression test for the
// Weekly variant, mirroring TestUnitCAScheduleDailyTimeRoundTrip: a
// buildSchedule call from config-shaped values must produce a wire Weekly
// object that scheduleToState maps back to the same day names (sorted for
// stable ordering) and time-of-day.
func TestUnitCAWeeklyScheduleRoundTrip(t *testing.T) {
	ctx := context.Background()
	// Deliberately unsorted input -- the wire/state round trip must still
	// produce a stably-sorted result.
	weeklyDays := stringSliceToTfList([]string{"Friday", "Monday"})

	sched, err := buildSchedule(ctx, types.Int64{Null: true}, types.String{Null: true}, weeklyDays, types.String{Value: "07:00:00"})
	if !assert.NoError(t, err) || !assert.NotNil(t, sched) || !assert.NotNil(t, sched.Weekly) {
		return
	}
	assert.ElementsMatch(t, []v1.SystemDayOfWeek{v1.SYSTEMDAYOFWEEK_Friday, v1.SYSTEMDAYOFWEEK_Monday}, sched.Weekly.Days)

	interval, daily, rtDays, rtTime := scheduleToState(sched)
	assert.True(t, interval.Null)
	assert.True(t, daily.Null)
	if assert.False(t, rtDays.Null) {
		var days []string
		diags := rtDays.ElementsAs(ctx, &days, false)
		assert.False(t, diags.HasError())
		assert.Equal(t, []string{"Monday", "Friday"}, days, "round trip must sort by enum value for stable ordering")
	}
	if assert.False(t, rtTime.Null) {
		assert.Equal(t, "07:00:00", rtTime.Value)
	}
}

// TestUnitCAWeeklyScheduleSentinelBuildsNilSchedule verifies buildSchedule's
// G2 weekly clear sentinel: an empty days list together with an empty time
// string contributes nothing to the built schedule, exactly like the
// interval=0/daily="" sentinels, so it round-trips to "omit the field" (which
// Command's full-replace PUT then interprets as a clear).
func TestUnitCAWeeklyScheduleSentinelBuildsNilSchedule(t *testing.T) {
	ctx := context.Background()
	emptyDays := stringSliceToTfList(nil)

	sched, err := buildSchedule(ctx, types.Int64{Null: true}, types.String{Null: true}, emptyDays, types.String{Value: ""})
	assert.NoError(t, err)
	assert.Nil(t, sched, "the weekly clear sentinel ([] + \"\") must contribute no schedule, matching the interval=0/daily=\"\" sentinels")
}

// TestUnitCAWeeklyScheduleMismatchedSentinelPairErrors covers buildSchedule's
// defense-in-depth mismatched-pair check: a real days list paired with an
// empty time (or vice versa) is neither a valid schedule nor a valid clear,
// and must be rejected rather than silently treated as one or the other.
func TestUnitCAWeeklyScheduleMismatchedSentinelPairErrors(t *testing.T) {
	ctx := context.Background()

	_, err := buildSchedule(ctx, types.Int64{Null: true}, types.String{Null: true}, stringSliceToTfList([]string{"Monday"}), types.String{Value: ""})
	assert.Error(t, err, "real days + empty time must be rejected as a mismatched pair")

	_, err = buildSchedule(ctx, types.Int64{Null: true}, types.String{Null: true}, stringSliceToTfList(nil), types.String{Value: "07:00:00"})
	assert.Error(t, err, "empty days + real time must be rejected as a mismatched pair")
}

// TestUnitCAUpdateWeeklyToIntervalVariantSwitchDoesNotResurrectOther is the
// Weekly/Interval switch case of the F182-1-class regression covered for
// Interval/Daily by TestUnitCAUpdateScheduleVariantSwitchDoesNotResurrectOther:
// a config-declared switch away from a live Weekly schedule to Interval must
// not resurrect the old Weekly value from prior state alongside the new one.
func TestUnitCAUpdateWeeklyToIntervalVariantSwitchDoesNotResurrectOther(t *testing.T) {
	ctx := context.Background()

	state := caAllSchedulesNull
	state.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday"})
	state.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	config := caAllSchedulesNull
	config.FullScanIntervalMinutes = types.Int64{Value: 60}
	plan := caAllSchedulesNull
	plan.FullScanIntervalMinutes = types.Int64{Value: 60}

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	if assert.NotNil(t, req.FullScan) {
		assert.Nil(t, req.FullScan.Weekly, "switching to Interval must not resurrect the old Weekly value from prior state")
		if assert.NotNil(t, req.FullScan.Interval) {
			assert.Equal(t, int32(60), *req.FullScan.Interval.Minutes)
		}
	}
}

// TestUnitCAUpdateIntervalToWeeklyVariantSwitchDoesNotResurrectOther is the
// reverse switch: Interval -> Weekly.
func TestUnitCAUpdateIntervalToWeeklyVariantSwitchDoesNotResurrectOther(t *testing.T) {
	ctx := context.Background()

	state := caAllSchedulesNull
	state.FullScanIntervalMinutes = types.Int64{Value: 60}

	config := caAllSchedulesNull
	config.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday"})
	config.FullScanWeeklyTime = types.String{Value: "07:00:00"}
	plan := caAllSchedulesNull
	plan.FullScanWeeklyDays = config.FullScanWeeklyDays
	plan.FullScanWeeklyTime = config.FullScanWeeklyTime

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	if assert.NotNil(t, req.FullScan) {
		assert.Nil(t, req.FullScan.Interval, "switching to Weekly must not resurrect the old Interval value from prior state")
		if assert.NotNil(t, req.FullScan.Weekly) {
			assert.Equal(t, []v1.SystemDayOfWeek{v1.SYSTEMDAYOFWEEK_Monday}, req.FullScan.Weekly.Days)
		}
	}
}

// TestUnitCAUpdateWeeklyToDailyVariantSwitchDoesNotResurrectOther covers the
// Weekly/Daily switch pair, the third combination alongside
// Weekly/Interval above.
func TestUnitCAUpdateWeeklyToDailyVariantSwitchDoesNotResurrectOther(t *testing.T) {
	ctx := context.Background()

	state := caAllSchedulesNull
	state.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday"})
	state.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	config := caAllSchedulesNull
	config.FullScanDailyTime = types.String{Value: "15:46:00"}
	plan := caAllSchedulesNull
	plan.FullScanDailyTime = types.String{Value: "15:46:00"}

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	if assert.NotNil(t, req.FullScan) {
		assert.Nil(t, req.FullScan.Weekly, "switching to Daily must not resurrect the old Weekly value from prior state")
		if assert.NotNil(t, req.FullScan.Daily) {
			assert.NotNil(t, req.FullScan.Daily.Time)
			assert.Equal(t, "15:46:00", req.FullScan.Daily.Time.UTC().Format(caDailyTimeLayout))
		}
	}
}

// TestUnitCAUpdateDailyToWeeklyVariantSwitchDoesNotResurrectOther is the
// reverse switch: Daily -> Weekly.
func TestUnitCAUpdateDailyToWeeklyVariantSwitchDoesNotResurrectOther(t *testing.T) {
	ctx := context.Background()

	state := caAllSchedulesNull
	state.FullScanDailyTime = types.String{Value: "15:46:00"}

	config := caAllSchedulesNull
	config.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday", "Friday"})
	config.FullScanWeeklyTime = types.String{Value: "07:00:00"}
	plan := caAllSchedulesNull
	plan.FullScanWeeklyDays = config.FullScanWeeklyDays
	plan.FullScanWeeklyTime = config.FullScanWeeklyTime

	preserveCAUpdateFields(ctx, &plan, config, state)
	req, buildDiags := buildCARequest(ctx, plan)
	assert.False(t, buildDiags.HasError(), "buildCARequest should not error: %v", buildDiags)

	if assert.NotNil(t, req.FullScan) {
		assert.Nil(t, req.FullScan.Daily, "switching to Weekly must not resurrect the old Daily value from prior state")
		if assert.NotNil(t, req.FullScan.Weekly) {
			assert.ElementsMatch(t, []v1.SystemDayOfWeek{v1.SYSTEMDAYOFWEEK_Monday, v1.SYSTEMDAYOFWEEK_Friday}, req.FullScan.Weekly.Days)
		}
	}
}

// TestUnitCAWeeklyScheduleSentinelClears is the framework-realistic
// Update()-level red/green regression test for the weekly clear sentinel,
// mirroring TestUnitCAScheduleSentinelClears: declaring the clear sentinel
// ([] + "") against a CA that currently has a live Weekly schedule must send
// a PUT that OMITS FullScan entirely, and the resulting post-apply state
// must carry the sentinel forward (sentinel stability), not the server's
// bare Null.
func TestUnitCAWeeklyScheduleSentinelClears(t *testing.T) {
	ctx := context.Background()

	var capturedPutBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/CertificateAuthority/50", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Still live at GET time -- the clear hasn't happened yet.
		_, _ = w.Write([]byte(`{
			"Id": 50,
			"LogicalName": "tf-unit-ca-weekly-sentinel-clear",
			"HostName": "ca.lab.example.com",
			"CAType": 1,
			"FullScan": {"Weekly": {"Days": ["Monday"], "Time": "2026-07-17T07:00:00Z"}}
		}`))
	})
	mux.HandleFunc("/KeyfactorAPI/CertificateAuthority", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		capturedPutBody = body

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Command cleared it: the response no longer carries a FullScan at all.
		_, _ = w.Write([]byte(`{
			"Id": 50,
			"LogicalName": "tf-unit-ca-weekly-sentinel-clear",
			"HostName": "ca.lab.example.com",
			"CAType": 1
		}`))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	sdkClient := newCAMockSDKClient(server)

	schema, sDiags := resourceCertificateAuthorityType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := caAllSchedulesNull
	state.ID = types.String{Value: "50"}
	state.LogicalName = types.String{Value: "tf-unit-ca-weekly-sentinel-clear"}
	state.HostName = types.String{Value: "ca.lab.example.com"}
	state.CAType = types.Int64{Value: 1}
	state.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday"})
	state.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	// Config: the practitioner declares the weekly clear sentinel directly.
	config := caAllSchedulesNull
	config.ID = state.ID
	config.LogicalName = state.LogicalName
	config.HostName = state.HostName
	config.CAType = state.CAType
	config.FullScanWeeklyDays = stringSliceToTfList(nil)
	config.FullScanWeeklyTime = types.String{Value: ""}

	// Plan: config declared the sentinel directly (Known), so a real
	// pairedWith-driven plan already carries it here without needing any
	// modifier intervention.
	plan := caAllSchedulesNull
	plan.ID = state.ID
	plan.LogicalName = state.LogicalName
	plan.HostName = state.HostName
	plan.CAType = state.CAType
	plan.FullScanWeeklyDays = config.FullScanWeeklyDays
	plan.FullScanWeeklyTime = config.FullScanWeeklyTime

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	configPlan := tfsdk.Plan{Schema: schema}
	if d := configPlan.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configPlan.Raw}

	r := resourceCertificateAuthority{p: provider{configured: true, sdkClient: sdkClient}}

	req := tfsdk.UpdateResourceRequest{Config: configObj, Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostic errors: %+v", resp.Diagnostics)
	}

	if len(capturedPutBody) == 0 {
		t.Fatal("expected the PUT /CertificateAuthority request body to have been captured")
	}

	var wire caWeeklyScheduleWireCapture
	if err := json.Unmarshal(capturedPutBody, &wire); err != nil {
		t.Fatalf("failed to unmarshal captured PUT body: %s\nbody: %s", err, capturedPutBody)
	}
	assert.Nil(t, wire.FullScan,
		"a declared weekly clear sentinel must send a PUT that OMITS FullScan entirely, not copy the still-live server schedule back in")

	var result KeyfactorCertificateAuthority
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("reading back result state: %+v", d)
	}
	if assert.False(t, result.FullScanWeeklyTime.Null,
		"post-apply state must keep the declared weekly clear sentinel, not surface the server's bare Null") {
		assert.Equal(t, "", result.FullScanWeeklyTime.Value)
	}
	if assert.False(t, result.FullScanWeeklyDays.Null) {
		var days []string
		result.FullScanWeeklyDays.ElementsAs(ctx, &days, false)
		assert.Empty(t, days)
	}
}

// TestUnitCAReadSurfacesWeeklyDriftOverSentinel is the weekly companion to
// TestUnitCAReadSurfacesDriftOverSentinel: when the server reports a REAL
// Weekly schedule (e.g. an out-of-band re-add via Command's UI) even though
// prior state held the declared weekly clear sentinel, Read must surface
// that as genuine drift, never mask it behind the stale sentinel.
func TestUnitCAReadSurfacesWeeklyDriftOverSentinel(t *testing.T) {
	weeklyTime := time.Date(2026, 7, 17, 7, 0, 0, 0, time.UTC)
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{
		FullScan: &v1.KeyfactorCommonSchedulingKeyfactorSchedule{
			Weekly: &v1.KeyfactorCommonSchedulingModelsWeeklyModel{
				Days: []v1.SystemDayOfWeek{v1.SYSTEMDAYOFWEEK_Monday},
				Time: &weeklyTime,
			},
		},
	}

	priorState := caAllSchedulesNull
	priorState.FullScanWeeklyDays = stringSliceToTfList(nil)
	priorState.FullScanWeeklyTime = types.String{Value: ""}

	newState := caResponseToState(resp)
	keepScheduleSentinels(context.Background(), &newState, priorState)

	if assert.False(t, newState.FullScanWeeklyDays.Null, "a real server-reported Weekly schedule must surface, not be masked by the stale sentinel") {
		var days []string
		newState.FullScanWeeklyDays.ElementsAs(context.Background(), &days, false)
		assert.Equal(t, []string{"Monday"}, days)
	}
	if assert.False(t, newState.FullScanWeeklyTime.Null) {
		assert.Equal(t, "07:00:00", newState.FullScanWeeklyTime.Value)
	}
}

// ---------------------------------------------------------------------------
// ValidateConfig coverage for the weekly variant
// ---------------------------------------------------------------------------

// TestUnitCAValidateConfigRejectsWeeklyDaysWithoutTime verifies the
// co-required rule: declaring full_scan_weekly_days without
// full_scan_weekly_time is rejected at plan time.
func TestUnitCAValidateConfigRejectsWeeklyDaysWithoutTime(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday"})

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.True(t, diags.HasError(), "declaring full_scan_weekly_days without full_scan_weekly_time must be a plan-time error")
}

// TestUnitCAValidateConfigRejectsWeeklyTimeWithoutDays is the reverse case.
func TestUnitCAValidateConfigRejectsWeeklyTimeWithoutDays(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.True(t, diags.HasError(), "declaring full_scan_weekly_time without full_scan_weekly_days must be a plan-time error")
}

// TestUnitCAValidateConfigRejectsInvalidWeeklyDayName verifies that a
// misspelled day name is rejected.
func TestUnitCAValidateConfigRejectsInvalidWeeklyDayName(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanWeeklyDays = stringSliceToTfList([]string{"Munday"})
	cfg.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.True(t, diags.HasError(), "an invalid day name must be a plan-time error")
}

// TestUnitCAValidateConfigRejectsLowercaseWeeklyDayName documents and
// enforces the case-handling decision: day names are exact and
// case-sensitive (matching Command's own canonical capitalization), not
// normalized, so a lowercase (or any other casing) variant is rejected
// rather than silently accepted -- this keeps state (always written in
// canonical form by scheduleToState) byte-for-byte comparable to config
// without needing a separate normalizing plan modifier.
func TestUnitCAValidateConfigRejectsLowercaseWeeklyDayName(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanWeeklyDays = stringSliceToTfList([]string{"monday"})
	cfg.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.True(t, diags.HasError(), "day names are exact and case-sensitive; a lowercase variant must be rejected")
}

// TestUnitCAValidateConfigRejectsMismatchedWeeklySentinelPair verifies the
// plan-time check for a declared-but-mismatched pair: an empty days list
// paired with a real time (or vice versa) is ambiguous and rejected, the
// same rationale buildSchedule's defense-in-depth check applies at apply
// time.
func TestUnitCAValidateConfigRejectsMismatchedWeeklySentinelPair(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanWeeklyDays = stringSliceToTfList(nil)
	cfg.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.True(t, diags.HasError(), "an empty days list paired with a real time must be a plan-time error")
}

// TestUnitCAValidateConfigRejectsWeeklyConflictingWithInterval verifies the
// three-way exclusivity: declaring both full_scan_interval_minutes and the
// weekly pair for the same schedule is a conflict, just like
// interval+daily was before Weekly existed.
func TestUnitCAValidateConfigRejectsWeeklyConflictingWithInterval(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanIntervalMinutes = types.Int64{Value: 60}
	cfg.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday"})
	cfg.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.True(t, diags.HasError(), "declaring both full_scan_interval_minutes and the weekly pair must be a plan-time error")
}

// TestUnitCAValidateConfigRejectsWeeklyConflictingWithDaily is the Daily
// half of the three-way exclusivity check.
func TestUnitCAValidateConfigRejectsWeeklyConflictingWithDaily(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanDailyTime = types.String{Value: "07:00:00"}
	cfg.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday"})
	cfg.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.True(t, diags.HasError(), "declaring both full_scan_daily_time and the weekly pair must be a plan-time error")
}

// TestUnitCAValidateConfigAllowsWeeklyAlone confirms the common, non-error
// case: a weekly schedule declared alone (both attributes, real values)
// passes validation cleanly.
func TestUnitCAValidateConfigAllowsWeeklyAlone(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanWeeklyDays = stringSliceToTfList([]string{"Monday", "Friday"})
	cfg.FullScanWeeklyTime = types.String{Value: "07:00:00"}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.False(t, diags.HasError(), "a weekly schedule declared alone must be valid: %+v", diags)
}

// TestUnitCAValidateConfigAllowsWeeklyClearSentinel confirms the weekly
// clear sentinel ([] + "") passes validation cleanly, the co-required and
// mismatched-pair checks must not treat "both empty" as an error.
func TestUnitCAValidateConfigAllowsWeeklyClearSentinel(t *testing.T) {
	cfg := caAllSchedulesNull
	cfg.FullScanWeeklyDays = stringSliceToTfList(nil)
	cfg.FullScanWeeklyTime = types.String{Value: ""}

	diags := validateCAScheduleAttributes(context.Background(), cfg)
	assert.False(t, diags.HasError(), "the weekly clear sentinel ([] + \"\") must be valid: %+v", diags)
}
