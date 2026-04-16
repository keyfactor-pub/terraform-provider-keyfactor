package keyfactor

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceApplicationType struct{}

func (r dataSourceApplicationType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"identifier": {
				Type:        types.StringType,
				Required:    true,
				Description: "The name or integer ID of the application to look up.",
			},
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Integer ID of the application in Keyfactor Command.",
			},
			"name": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Name of the application.",
			},
			"overwrite_schedules": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether the application schedule overwrites member certificate store schedules.",
			},
			"schedule_immediate": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "True if an immediate one-shot inventory run is configured.",
			},
			"schedule_interval_minutes": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Inventory schedule interval in minutes, if an interval-based schedule is configured.",
			},
			"schedule_daily_time": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Inventory schedule daily time as an ISO 8601 datetime string, if a daily schedule is configured.",
			},
			"schedule_weekly_days": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "Days of the week for a weekly schedule (e.g. [\"Monday\", \"Wednesday\"]).",
			},
			"schedule_weekly_time": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Time-of-day for the weekly schedule as an ISO 8601 datetime string.",
			},
			"schedule_monthly_day": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Day of the month for a monthly schedule (1–31).",
			},
			"schedule_monthly_time": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Time-of-day for the monthly schedule as an ISO 8601 datetime string.",
			},
			"schedule_exactly_once_time": {
				Type:        types.StringType,
				Computed:    true,
				Description: "ISO 8601 datetime string if inventory is scheduled to run exactly once.",
			},
			"certificate_store_ids": {
				Type:        types.ListType{ElemType: types.StringType},
				Computed:    true,
				Description: "List of certificate store GUIDs (UUIDs) assigned to this application.",
			},
		},
		MarkdownDescription: `
Reads an existing Keyfactor Command Application (certificate store container).

> [!NOTE]
> On Keyfactor Command v25.0+ this data source uses the ` + "`/Applications`" + ` endpoint.
> On pre-v25 Command it automatically falls back to ` + "`/CertificateStoreContainers`" + `.
`,
	}, nil
}

func (r dataSourceApplicationType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceApplication{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceApplication struct {
	p provider
}

// KeyfactorApplicationDataSource is the Terraform state model for data.keyfactor_application.
type KeyfactorApplicationDataSource struct {
	Identifier           types.String `tfsdk:"identifier"`
	ID                   types.Int64  `tfsdk:"id"`
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
	CertificateStoreIDs  types.List   `tfsdk:"certificate_store_ids"`
}

func (r dataSourceApplication) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	LogFunctionEntry(ctx, "dataSourceApplication.Read")

	var state KeyfactorApplicationDataSource
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	identifier := state.Identifier.Value
	tflog.Info(ctx, fmt.Sprintf("Reading application with identifier %q", identifier))

	// Try to parse as integer ID first, then fall back to name lookup.
	var appID int
	if id, err := strconv.Atoi(identifier); err == nil {
		appID = id
		tflog.Debug(ctx, fmt.Sprintf("Identifier is numeric, using ID %d", appID))
	} else {
		// Look up by name via the list endpoint.
		apps, listErr := r.p.client.ListApplications()
		if listErr != nil {
			response.Diagnostics.AddError(
				"Error listing applications.",
				"Could not list applications from Keyfactor Command: "+listErr.Error(),
			)
			return
		}
		found := false
		for _, app := range apps {
			if app.Name == identifier {
				appID = app.Id
				found = true
				break
			}
		}
		if !found {
			response.Diagnostics.AddError(
				"Application not found.",
				fmt.Sprintf("No application with name %q was found in Keyfactor Command.", identifier),
			)
			return
		}
	}

	app, err := r.p.client.GetApplication(appID)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading application.",
			fmt.Sprintf("Could not read application %d from Keyfactor Command: %s", appID, err.Error()),
		)
		return
	}

	immediate, intervalMins, dailyTime, weeklyDays, weeklyTime, monthlyDay, monthlyTime, exactlyOnce := flattenApplicationSchedule(app.Schedule)

	// Build the certificate_store_ids list.
	storeIDs := make([]string, 0, len(app.CertificateStores))
	for _, cs := range app.CertificateStores {
		storeIDs = append(storeIDs, cs.Id)
	}
	storeIDList := types.List{
		ElemType: types.StringType,
		Elems:    convertStringArrayToTerraform(storeIDs),
	}

	result := KeyfactorApplicationDataSource{
		Identifier:           state.Identifier,
		ID:                   types.Int64{Value: int64(app.Id)},
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
		CertificateStoreIDs:  storeIDList,
	}

	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	LogFunctionExit(ctx, "dataSourceApplication.Read")
}
