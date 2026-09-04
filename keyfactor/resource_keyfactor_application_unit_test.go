package keyfactor

import (
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitApplicationUpdatePreservesScheduleImmediate exercises the Update→Read
// round trip when the user planned schedule_immediate = true. Command queues the
// job and persists it as ExactlyOnce, so the API response no longer carries
// Immediate. Without the preservation helper, the state set by Update would
// disagree with the plan (Null vs true), triggering "inconsistent result after
// apply" in the framework.
func TestUnitApplicationUpdatePreservesScheduleImmediate(t *testing.T) {
	cases := []struct {
		name     string
		schedule *api.ApplicationSchedule
	}{
		{
			name:     "server omits schedule field entirely",
			schedule: nil,
		},
		{
			name: "server converts immediate to exactly_once",
			schedule: &api.ApplicationSchedule{
				ExactlyOnce: &api.ApplicationScheduleDaily{Time: "2026-04-28T12:00:00Z"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := KeyfactorApplication{
				ScheduleImmediate: types.Bool{Value: true},
			}
			serverResp := &api.ApplicationResponse{
				Id:       42,
				Name:     "tf-unit-app",
				Schedule: tc.schedule,
			}

			newState := applicationResponseToState(serverResp)
			assert.True(t, newState.ScheduleImmediate.Null,
				"sanity check: API response should not carry immediate=true")

			preserveApplicationScheduleFields(plan, &newState)

			assert.False(t, newState.ScheduleImmediate.Null,
				"schedule_immediate must not be null after preservation")
			assert.False(t, newState.ScheduleImmediate.Unknown,
				"schedule_immediate must not be unknown after preservation")
			assert.True(t, newState.ScheduleImmediate.Value,
				"schedule_immediate must remain true to match the plan")
		})
	}
}

// TestUnitApplicationUpdateScheduleImmediateNullPlan verifies the helper does
// not invent a value when the caller did not request immediate. A null plan
// stays null in state.
func TestUnitApplicationUpdateScheduleImmediateNullPlan(t *testing.T) {
	plan := KeyfactorApplication{
		ScheduleImmediate: types.Bool{Null: true},
	}
	serverResp := &api.ApplicationResponse{Id: 1, Name: "noop", Schedule: nil}

	newState := applicationResponseToState(serverResp)
	preserveApplicationScheduleFields(plan, &newState)

	assert.True(t, newState.ScheduleImmediate.Null,
		"null plan must yield null state : preservation is one-way (true only)")
}

// TestUnitApplicationUpdateNormalizesScheduleTimes verifies that datetime
// schedule fields are kept stable across the Update→Read cycle when the server
// only advances the date portion (same time-of-day).
func TestUnitApplicationUpdateNormalizesScheduleTimes(t *testing.T) {
	cases := []struct {
		name       string
		field      string
		planTime   string
		serverResp *api.ApplicationResponse
		extract    func(s KeyfactorApplication) types.String
	}{
		{
			name:     "daily time preserved when only date advances",
			field:    "ScheduleDailyTime",
			planTime: "2023-11-25T23:30:00Z",
			serverResp: &api.ApplicationResponse{Id: 1, Name: "x", Schedule: &api.ApplicationSchedule{
				Daily: &api.ApplicationScheduleDaily{Time: "2026-04-28T23:30:00Z"},
			}},
			extract: func(s KeyfactorApplication) types.String { return s.ScheduleDailyTime },
		},
		{
			name:     "weekly time preserved when only date advances",
			field:    "ScheduleWeeklyTime",
			planTime: "2023-11-25T08:00:00Z",
			serverResp: &api.ApplicationResponse{Id: 1, Name: "x", Schedule: &api.ApplicationSchedule{
				Weekly: &api.ApplicationScheduleWeekly{
					Days: []string{"Monday"}, Time: "2026-05-04T08:00:00Z",
				},
			}},
			extract: func(s KeyfactorApplication) types.String { return s.ScheduleWeeklyTime },
		},
		{
			name:     "monthly time preserved when only date advances",
			field:    "ScheduleMonthlyTime",
			planTime: "2023-11-25T15:45:00Z",
			serverResp: &api.ApplicationResponse{Id: 1, Name: "x", Schedule: &api.ApplicationSchedule{
				Monthly: &api.ApplicationScheduleMonthly{Day: 25, Time: "2026-05-25T15:45:00Z"},
			}},
			extract: func(s KeyfactorApplication) types.String { return s.ScheduleMonthlyTime },
		},
		{
			name:     "exactly_once time preserved when only date advances",
			field:    "ScheduleExactlyOnce",
			planTime: "2023-11-25T02:00:00Z",
			serverResp: &api.ApplicationResponse{Id: 1, Name: "x", Schedule: &api.ApplicationSchedule{
				ExactlyOnce: &api.ApplicationScheduleDaily{Time: "2026-04-29T02:00:00Z"},
			}},
			extract: func(s KeyfactorApplication) types.String { return s.ScheduleExactlyOnce },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := KeyfactorApplication{}
			switch tc.field {
			case "ScheduleDailyTime":
				plan.ScheduleDailyTime = types.String{Value: tc.planTime}
			case "ScheduleWeeklyTime":
				plan.ScheduleWeeklyTime = types.String{Value: tc.planTime}
			case "ScheduleMonthlyTime":
				plan.ScheduleMonthlyTime = types.String{Value: tc.planTime}
			case "ScheduleExactlyOnce":
				plan.ScheduleExactlyOnce = types.String{Value: tc.planTime}
			}

			newState := applicationResponseToState(tc.serverResp)
			preserveApplicationScheduleFields(plan, &newState)

			got := tc.extract(newState)
			assert.Equal(t, tc.planTime, got.Value,
				"%s: expected plan datetime %q to be preserved, got %q",
				tc.field, tc.planTime, got.Value)
		})
	}
}

// TestUnitApplicationUpdateReplacesScheduleTimeWhenTimeOfDayChanges verifies the
// inverse: when the time-of-day actually differs, the helper accepts the
// server's value (so legitimate drift detection still works).
func TestUnitApplicationUpdateReplacesScheduleTimeWhenTimeOfDayChanges(t *testing.T) {
	plan := KeyfactorApplication{
		ScheduleDailyTime: types.String{Value: "2023-11-25T23:30:00Z"},
	}
	serverResp := &api.ApplicationResponse{Id: 1, Name: "x", Schedule: &api.ApplicationSchedule{
		Daily: &api.ApplicationScheduleDaily{Time: "2026-04-28T01:15:00Z"},
	}}

	newState := applicationResponseToState(serverResp)
	preserveApplicationScheduleFields(plan, &newState)

	assert.Equal(t, "2026-04-28T01:15:00Z", newState.ScheduleDailyTime.Value,
		"different time-of-day must NOT be coerced back to the plan value")
}
