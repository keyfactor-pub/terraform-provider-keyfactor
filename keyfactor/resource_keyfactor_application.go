package keyfactor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
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
			"schedule_interval_minutes": {
				Type:        types.Int64Type,
				Optional:    true,
				Description: "Inventory schedule interval in minutes. Set to a positive integer to use an interval-based schedule. Mutually exclusive with schedule_daily_time.",
			},
			"schedule_daily_time": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Inventory schedule daily time as an ISO 8601 datetime string (e.g. '2023-11-25T23:30:00Z'). Mutually exclusive with schedule_interval_minutes.",
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
> Applications are only available in Keyfactor Command v25.0+
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
	ScheduleIntervalMins types.Int64  `tfsdk:"schedule_interval_minutes"`
	ScheduleDailyTime    types.String `tfsdk:"schedule_daily_time"`
	StoreCount           types.Int64  `tfsdk:"store_count"`
}

// buildApplicationSchedule converts Terraform model fields into an API schedule object.
func buildApplicationSchedule(intervalMins types.Int64, dailyTime types.String) *api.ApplicationSchedule {
	if !intervalMins.Null && !intervalMins.Unknown && intervalMins.Value > 0 {
		return &api.ApplicationSchedule{
			Interval: &api.ApplicationScheduleInterval{Minutes: int(intervalMins.Value)},
		}
	}
	if !dailyTime.Null && !dailyTime.Unknown && dailyTime.Value != "" {
		return &api.ApplicationSchedule{
			Daily: &api.ApplicationScheduleDaily{Time: dailyTime.Value},
		}
	}
	return nil
}

// flattenApplicationSchedule converts an API schedule object into Terraform model fields.
func flattenApplicationSchedule(sched *api.ApplicationSchedule) (types.Int64, types.String) {
	if sched == nil {
		return types.Int64{Null: true}, types.String{Null: true}
	}
	if sched.Interval != nil {
		return types.Int64{Value: int64(sched.Interval.Minutes)}, types.String{Null: true}
	}
	if sched.Daily != nil {
		return types.Int64{Null: true}, types.String{Value: sched.Daily.Time}
	}
	return types.Int64{Null: true}, types.String{Null: true}
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
		Schedule:           buildApplicationSchedule(plan.ScheduleIntervalMins, plan.ScheduleDailyTime),
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
	// The server normalizes daily schedule times by updating the date to the next
	// occurrence. Preserve the state's date string if only the date portion changed
	// (same time-of-day) to avoid infinite plan drift.
	if !state.ScheduleDailyTime.Null && !state.ScheduleDailyTime.Unknown &&
		!newState.ScheduleDailyTime.Null && !newState.ScheduleDailyTime.Unknown {
		if dailyTimePortion(state.ScheduleDailyTime.Value) == dailyTimePortion(newState.ScheduleDailyTime.Value) {
			newState.ScheduleDailyTime = state.ScheduleDailyTime
		}
	}

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
		Schedule:           buildApplicationSchedule(plan.ScheduleIntervalMins, plan.ScheduleDailyTime),
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

// applicationResponseToState converts an API response to a Terraform state model.
func applicationResponseToState(app *api.ApplicationResponse) KeyfactorApplication {
	intervalMins, dailyTime := flattenApplicationSchedule(app.Schedule)
	return KeyfactorApplication{
		ID:                   types.String{Value: strconv.Itoa(app.Id)},
		Name:                 types.String{Value: app.Name},
		OverwriteSchedules:   types.Bool{Value: app.OverwriteSchedules},
		ScheduleIntervalMins: intervalMins,
		ScheduleDailyTime:    dailyTime,
		StoreCount:           types.Int64{Value: int64(len(app.CertificateStores))},
	}
}

