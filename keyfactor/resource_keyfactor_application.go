package keyfactor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceApplicationType struct{}

func (r resourceApplicationType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:          types.StringType,
				Computed:      true,
				Description:   "Keyfactor Command application ID.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"name": {
				Type:        types.StringType,
				Required:    true,
				Description: "Name of the application (certificate store container).",
			},
			"overwrite_schedules": {
				Type:          types.BoolType,
				Optional:      true,
				Computed:      true,
				Description:   "When true, the application schedule overwrites the schedules of all member certificate stores.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
			"schedule_immediate": {
				Type:        types.BoolType,
				Optional:    true,
				Description: "When true, schedules an immediate one-shot inventory run. Note: after the job executes the server may convert this to an ExactlyOnce entry, causing plan drift on the next refresh.",
			},
			"schedule_interval_minutes": {
				Type:        types.Int64Type,
				Optional:    true,
				Description: "Inventory schedule interval in minutes (e.g. 60 for hourly). Mutually exclusive with all other schedule_* attributes.",
			},
			"schedule_daily_time": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Inventory schedule daily time as an ISO 8601 datetime string (e.g. '2023-11-25T23:30:00Z'). Only the time-of-day portion is significant; the date is normalized by the server. Mutually exclusive with all other schedule_* attributes.",
			},
			"schedule_weekly_days": {
				Type:        types.ListType{ElemType: types.StringType},
				Optional:    true,
				Description: "Days of the week for a weekly inventory schedule. Accepted values: Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday. Requires schedule_weekly_time. Mutually exclusive with all other schedule_* attributes.",
			},
			"schedule_weekly_time": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Time-of-day for the weekly schedule as an ISO 8601 datetime string. Required when schedule_weekly_days is set.",
			},
			"schedule_monthly_day": {
				Type:        types.Int64Type,
				Optional:    true,
				Description: "Day of the month (1–31) for a monthly inventory schedule. Requires schedule_monthly_time. Mutually exclusive with all other schedule_* attributes.",
			},
			"schedule_monthly_time": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Time-of-day for the monthly schedule as an ISO 8601 datetime string. Required when schedule_monthly_day is set.",
			},
			"schedule_exactly_once_time": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Run inventory exactly once at the specified ISO 8601 UTC datetime (e.g. '2025-06-01T02:00:00Z'). Mutually exclusive with all other schedule_* attributes.",
			},
			"store_count": {
				Type:          types.Int64Type,
				Computed:      true,
				Description:   "Number of certificate stores currently assigned to this application.",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			},
		},
		MarkdownDescription: `
Manages a Keyfactor Command Application (certificate store container).

Applications group certificate stores together and define an optional inventory schedule that applies to all member stores.

> [!NOTE]
> On Keyfactor Command v25.0+ this resource uses the ` + "`/Applications`" + ` endpoint.
> On pre-v25 Command it automatically falls back to ` + "`/CertificateStoreContainers`" + `,
> which supports the same schedule types and JSON format.
`,
	}, nil
}

func (r resourceApplicationType) NewResource(ctx context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceApplication{
		p: *(p.(*provider)),
	}, nil
}

type resourceApplication struct {
	p provider
}

// KeyfactorApplication is the Terraform state model for keyfactor_application.
type KeyfactorApplication struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	OverwriteSchedules   types.Bool   `tfsdk:"overwrite_schedules"`
	ScheduleImmediate    types.Bool   `tfsdk:"schedule_immediate"`
	ScheduleIntervalMins types.Int64  `tfsdk:"schedule_interval_minutes"`
	ScheduleDailyTime    types.String `tfsdk:"schedule_daily_time"`
	ScheduleWeeklyDays   types.List   `tfsdk:"schedule_weekly_days"`
	ScheduleWeeklyTime   types.String `tfsdk:"schedule_weekly_time"`
	ScheduleMonthlyDay   types.Int64  `tfsdk:"schedule_monthly_day"`
	ScheduleMonthlyTime  types.String `tfsdk:"schedule_monthly_time"`
	ScheduleExactlyOnce  types.String `tfsdk:"schedule_exactly_once_time"`
	StoreCount           types.Int64  `tfsdk:"store_count"`
}

// nullScheduleFields returns zero-value (null) schedule fields for the state model.
func nullScheduleFields() (types.Bool, types.Int64, types.String, types.List, types.String, types.Int64, types.String, types.String) {
	nullList := types.List{Null: true, ElemType: types.StringType}
	return types.Bool{Null: true},
		types.Int64{Null: true},
		types.String{Null: true},
		nullList,
		types.String{Null: true},
		types.Int64{Null: true},
		types.String{Null: true},
		types.String{Null: true}
}

// buildApplicationSchedule converts Terraform model fields into an API schedule object.
func buildApplicationSchedule(state KeyfactorApplication) *api.ApplicationSchedule {
	if !state.ScheduleImmediate.Null && !state.ScheduleImmediate.Unknown && state.ScheduleImmediate.Value {
		t := true
		return &api.ApplicationSchedule{Immediate: &t}
	}
	if !state.ScheduleIntervalMins.Null && !state.ScheduleIntervalMins.Unknown && state.ScheduleIntervalMins.Value > 0 {
		return &api.ApplicationSchedule{
			Interval: &api.ApplicationScheduleInterval{Minutes: int(state.ScheduleIntervalMins.Value)},
		}
	}
	if !state.ScheduleDailyTime.Null && !state.ScheduleDailyTime.Unknown && state.ScheduleDailyTime.Value != "" {
		return &api.ApplicationSchedule{
			Daily: &api.ApplicationScheduleDaily{Time: state.ScheduleDailyTime.Value},
		}
	}
	if !state.ScheduleWeeklyTime.Null && !state.ScheduleWeeklyTime.Unknown && state.ScheduleWeeklyTime.Value != "" {
		days := make([]string, 0, len(state.ScheduleWeeklyDays.Elems))
		for _, e := range state.ScheduleWeeklyDays.Elems {
			if s, ok := e.(types.String); ok {
				days = append(days, s.Value)
			}
		}
		return &api.ApplicationSchedule{
			Weekly: &api.ApplicationScheduleWeekly{Days: days, Time: state.ScheduleWeeklyTime.Value},
		}
	}
	if !state.ScheduleMonthlyDay.Null && !state.ScheduleMonthlyDay.Unknown && state.ScheduleMonthlyDay.Value > 0 &&
		!state.ScheduleMonthlyTime.Null && !state.ScheduleMonthlyTime.Unknown && state.ScheduleMonthlyTime.Value != "" {
		return &api.ApplicationSchedule{
			Monthly: &api.ApplicationScheduleMonthly{
				Day:  int(state.ScheduleMonthlyDay.Value),
				Time: state.ScheduleMonthlyTime.Value,
			},
		}
	}
	if !state.ScheduleExactlyOnce.Null && !state.ScheduleExactlyOnce.Unknown && state.ScheduleExactlyOnce.Value != "" {
		return &api.ApplicationSchedule{
			ExactlyOnce: &api.ApplicationScheduleDaily{Time: state.ScheduleExactlyOnce.Value},
		}
	}
	// No schedule_* attribute is active in the plan. Return the SDK-documented
	// empty-object "disable" payload rather than a bare nil.
	//
	// UpdateApplication performs a *full replacement* of the application (see
	// its doc comment in keyfactor-go-client/v3/api/application.go), and
	// ApplicationUpdateRequest.Schedule is `json:"Schedule,omitempty"`. Returning
	// nil therefore omits the Schedule field from the PUT body entirely, leaving
	// the server free to preserve a real prior schedule on an otherwise unrelated
	// Update — which then disagrees with the plan (which declared no schedule)
	// and trips the framework's "inconsistent result after apply" check. Because
	// the endpoint fully replaces the resource there is no way to "omit to
	// preserve"; the ApplicationSchedule doc documents that the empty object is
	// the disable ("Off") signal, so send it explicitly. This applies equally
	// whether the schedule_* fields are genuinely undeclared (all null) or
	// explicitly zeroed — both mean "no schedule" for these Optional-only
	// attributes and must resolve to the same disable payload.
	return &api.ApplicationSchedule{}
}

// flattenApplicationSchedule converts an API schedule object into Terraform schedule fields.
func flattenApplicationSchedule(sched *api.ApplicationSchedule) (
	immediate types.Bool,
	intervalMins types.Int64,
	dailyTime types.String,
	weeklyDays types.List,
	weeklyTime types.String,
	monthlyDay types.Int64,
	monthlyTime types.String,
	exactlyOnce types.String,
) {
	immediate, intervalMins, dailyTime, weeklyDays, weeklyTime, monthlyDay, monthlyTime, exactlyOnce = nullScheduleFields()
	if sched == nil {
		return
	}
	if sched.Immediate != nil && *sched.Immediate {
		immediate = types.Bool{Value: true}
		return
	}
	if sched.Interval != nil {
		intervalMins = types.Int64{Value: int64(sched.Interval.Minutes)}
		return
	}
	if sched.Daily != nil {
		dailyTime = types.String{Value: sched.Daily.Time}
		return
	}
	if sched.Weekly != nil {
		elems := make([]attr.Value, len(sched.Weekly.Days))
		for i, d := range sched.Weekly.Days {
			elems[i] = types.String{Value: d}
		}
		weeklyDays = types.List{ElemType: types.StringType, Elems: elems}
		weeklyTime = types.String{Value: sched.Weekly.Time}
		return
	}
	if sched.Monthly != nil {
		monthlyDay = types.Int64{Value: int64(sched.Monthly.Day)}
		monthlyTime = types.String{Value: sched.Monthly.Time}
		return
	}
	if sched.ExactlyOnce != nil {
		exactlyOnce = types.String{Value: sched.ExactlyOnce.Time}
		return
	}
	return
}

func (r resourceApplication) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	LogFunctionEntry(ctx, "resourceApplication.Create")

	var plan KeyfactorApplication
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Creating application %q", plan.Name.Value))

	createReq := &api.ApplicationCreateRequest{
		Name:               plan.Name.Value,
		OverwriteSchedules: !plan.OverwriteSchedules.Null && plan.OverwriteSchedules.Value,
		Schedule:           buildApplicationSchedule(plan),
	}

	app, err := r.p.client.CreateApplication(createReq)
	if err != nil {
		response.Diagnostics.AddError(
			"Error creating application.",
			"Could not create application in Keyfactor Command: "+err.Error(),
		)
		return
	}

	state := applicationResponseToState(app)
	// OverwriteSchedules is not returned by the API; preserve the plan value.
	// Default to false if the user did not specify it (plan is Unknown or Null).
	if plan.OverwriteSchedules.Unknown || plan.OverwriteSchedules.Null {
		state.OverwriteSchedules = types.Bool{Value: false}
	} else {
		state.OverwriteSchedules = plan.OverwriteSchedules
	}
	preserveApplicationScheduleFields(plan, &state)

	diags = response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceApplication.Create")
}

func (r resourceApplication) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	LogFunctionEntry(ctx, "resourceApplication.Read")

	var state KeyfactorApplication
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	idStr := state.ID.Value
	id, err := strconv.Atoi(idStr)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid application ID.",
			fmt.Sprintf("Could not parse application ID %q: %s", idStr, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Reading application ID %d", id))

	app, err := r.p.client.GetApplication(id)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading application.",
			fmt.Sprintf("Could not read application %d from Keyfactor Command: %s", id, err.Error()),
		)
		return
	}

	newState := applicationResponseToState(app)
	// OverwriteSchedules is not returned by the API; preserve the existing state value.
	newState.OverwriteSchedules = state.OverwriteSchedules
	preserveApplicationScheduleFields(state, &newState)

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceApplication.Read")
}

func (r resourceApplication) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	LogFunctionEntry(ctx, "resourceApplication.Update")

	var plan KeyfactorApplication
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var state KeyfactorApplication
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid application ID.",
			fmt.Sprintf("Could not parse application ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Updating application ID %d", id))

	updateReq := &api.ApplicationUpdateRequest{
		Name:               plan.Name.Value,
		OverwriteSchedules: !plan.OverwriteSchedules.Null && plan.OverwriteSchedules.Value,
		Schedule:           buildApplicationSchedule(plan),
	}

	app, err := r.p.client.UpdateApplication(id, updateReq)
	if err != nil {
		response.Diagnostics.AddError(
			"Error updating application.",
			fmt.Sprintf("Could not update application %d in Keyfactor Command: %s", id, err.Error()),
		)
		return
	}

	newState := applicationResponseToState(app)
	// OverwriteSchedules is not returned by the API; preserve the plan value.
	newState.OverwriteSchedules = plan.OverwriteSchedules
	preserveApplicationScheduleFields(plan, &newState)

	diags = response.State.Set(ctx, &newState)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceApplication.Update")
}

func (r resourceApplication) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	LogFunctionEntry(ctx, "resourceApplication.Delete")

	var state KeyfactorApplication
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.Value)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid application ID.",
			fmt.Sprintf("Could not parse application ID %q: %s", state.ID.Value, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Deleting application ID %d", id))

	err = r.p.client.DeleteApplication(id)
	if err != nil {
		response.Diagnostics.AddError(
			"Error deleting application.",
			fmt.Sprintf("Could not delete application %d from Keyfactor Command: %s", id, err.Error()),
		)
		return
	}

	LogFunctionExit(ctx, "resourceApplication.Delete")
}

func (r resourceApplication) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	LogFunctionEntry(ctx, "resourceApplication.ImportState")

	id, err := strconv.Atoi(request.ID)
	if err != nil {
		response.Diagnostics.AddError(
			"Invalid import ID.",
			fmt.Sprintf("Application import ID must be a numeric integer, got %q: %s", request.ID, err.Error()),
		)
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Importing application ID %d", id))

	app, err := r.p.client.GetApplication(id)
	if err != nil {
		response.Diagnostics.AddError(
			"Error importing application.",
			fmt.Sprintf("Could not read application %d from Keyfactor Command: %s", id, err.Error()),
		)
		return
	}

	state := applicationResponseToState(app)
	// overwrite_schedules is not returned by the API; default to false on import.
	state.OverwriteSchedules = types.Bool{Value: false}

	diags := response.State.Set(ctx, &state)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "resourceApplication.ImportState")
}

// dailyTimePortion extracts the time-of-day portion from an ISO 8601 datetime string.
// For example, "2023-11-25T23:30:00Z" returns "T23:30:00Z".
// This is used to compare daily schedule times ignoring the date portion, since the
// server normalizes the date to the next scheduled occurrence.
func dailyTimePortion(datetime string) string {
	if idx := strings.Index(datetime, "T"); idx >= 0 {
		return datetime[idx:]
	}
	return datetime
}

// preserveApplicationScheduleFields reconciles server-returned schedule fields with the
// caller-supplied (plan or state) values to avoid "inconsistent result after apply"
// drift across Create→Read, Update→Read, and Read→Read cycles. It mutates newState
// in place. Two server behaviours are handled:
//   - Datetime fields (Daily/Weekly/Monthly/ExactlyOnce times) are normalised by the
//     server to the next scheduled occurrence; preserve the caller's datetime when
//     only the date portion changed (same time-of-day).
//   - schedule_immediate is a write-only trigger; the server converts it to
//     ExactlyOnce after queueing, so preserve a true value supplied by the caller.
func preserveApplicationScheduleFields(src KeyfactorApplication, newState *KeyfactorApplication) {
	preserveIfSameTime := func(srcVal, newVal types.String) types.String {
		if !srcVal.Null && !srcVal.Unknown && !newVal.Null && !newVal.Unknown {
			if dailyTimePortion(srcVal.Value) == dailyTimePortion(newVal.Value) {
				return srcVal
			}
		}
		return newVal
	}
	newState.ScheduleDailyTime = preserveIfSameTime(src.ScheduleDailyTime, newState.ScheduleDailyTime)
	newState.ScheduleWeeklyTime = preserveIfSameTime(src.ScheduleWeeklyTime, newState.ScheduleWeeklyTime)
	newState.ScheduleMonthlyTime = preserveIfSameTime(src.ScheduleMonthlyTime, newState.ScheduleMonthlyTime)
	newState.ScheduleExactlyOnce = preserveIfSameTime(src.ScheduleExactlyOnce, newState.ScheduleExactlyOnce)
	if !src.ScheduleImmediate.Null && !src.ScheduleImmediate.Unknown && src.ScheduleImmediate.Value {
		newState.ScheduleImmediate = src.ScheduleImmediate
	}
}

// applicationResponseToState converts an API response to a Terraform state model.
func applicationResponseToState(app *api.ApplicationResponse) KeyfactorApplication {
	immediate, intervalMins, dailyTime, weeklyDays, weeklyTime, monthlyDay, monthlyTime, exactlyOnce := flattenApplicationSchedule(app.Schedule)
	return KeyfactorApplication{
		ID:                   types.String{Value: strconv.Itoa(app.Id)},
		Name:                 types.String{Value: app.Name},
		OverwriteSchedules:   types.Bool{Value: app.OverwriteSchedules},
		ScheduleImmediate:    immediate,
		ScheduleIntervalMins: intervalMins,
		ScheduleDailyTime:    dailyTime,
		ScheduleWeeklyDays:   weeklyDays,
		ScheduleWeeklyTime:   weeklyTime,
		ScheduleMonthlyDay:   monthlyDay,
		ScheduleMonthlyTime:  monthlyTime,
		ScheduleExactlyOnce:  exactlyOnce,
		StoreCount:           types.Int64{Value: int64(len(app.CertificateStores))},
	}
}
