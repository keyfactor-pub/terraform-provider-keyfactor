package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Acceptance tests (TF_ACC=1, reads env vars for config)
// ---------------------------------------------------------------------------

// TestAccKeyfactorApplicationResource tests the full create/update/delete lifecycle
// of the keyfactor_application resource against a live Keyfactor Command instance.
//
// Required env vars (same as all TestAcc* tests): KEYFACTOR_HOSTNAME + auth creds.
// Optional: KEYFACTOR_APPLICATION_NAME overrides the application name used (a unique
// suffix is appended to avoid conflicts).
func TestAccKeyfactorApplicationResource(t *testing.T) {
	baseName := os.Getenv("KEYFACTOR_APPLICATION_NAME")
	if baseName == "" {
		baseName = "tf-acc-app"
	}
	// Append a short timestamp suffix so parallel runs don't collide.
	appName := fmt.Sprintf("%s-%d", baseName, time.Now().UnixNano()%1000000000)
	resourceName := "keyfactor_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with interval schedule
			{
				Config: testAccApplicationConfig(appName, false, 60, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					resource.TestCheckResourceAttr(resourceName, "overwrite_schedules", "false"),
					resource.TestCheckResourceAttr(resourceName, "schedule_interval_minutes", "60"),
					resource.TestCheckResourceAttrSet(resourceName, "store_count"),
				),
			},
			// Update schedule to a shorter interval
			{
				Config: testAccApplicationConfig(appName, false, 30, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					resource.TestCheckResourceAttr(resourceName, "schedule_interval_minutes", "30"),
				),
			},
			// Update to daily schedule
			{
				Config: testAccApplicationConfig(appName, false, 0, "2023-11-25T23:30:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					resource.TestCheckResourceAttr(resourceName, "schedule_daily_time", "2023-11-25T23:30:00Z"),
				),
			},
			// Remove schedule (minimal config)
			{
				Config: testAccApplicationConfigMinimal(appName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
				),
			},
		},
	})
}

// TestAccKeyfactorApplicationResourceOverwriteSchedules tests the overwrite_schedules flag.
func TestAccKeyfactorApplicationResourceOverwriteSchedules(t *testing.T) {
	baseName := os.Getenv("KEYFACTOR_APPLICATION_NAME")
	if baseName == "" {
		baseName = "tf-acc-app-ow"
	}
	appName := fmt.Sprintf("%s-%d", baseName, time.Now().UnixNano()%1000000000)
	resourceName := "keyfactor_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfig(appName, true, 120, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					resource.TestCheckResourceAttr(resourceName, "overwrite_schedules", "true"),
					resource.TestCheckResourceAttr(resourceName, "schedule_interval_minutes", "120"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorApplicationResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	appName := randomTestCN("tf-int-app")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create with interval schedule
				Config: testAccApplicationConfig(appName, false, 60, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_interval_minutes", "60"),
				),
			},
			{
				// Update: change name and schedule
				Config: testAccApplicationConfig(appName+"-updated", false, 30, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName+"-updated"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_interval_minutes", "30"),
				),
			},
			{
				// Update: switch to daily schedule
				Config: testAccApplicationConfig(appName+"-updated", false, 0, "2023-11-25T23:30:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_daily_time", "2023-11-25T23:30:00Z"),
				),
			},
		},
	})
}

func TestIntKeyfactorApplicationResourceNoSchedule(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	appName := randomTestCN("tf-int-app-ns")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigMinimal(appName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
				),
			},
		},
	})
}

func TestIntKeyfactorApplicationResourceWeeklySchedule(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}
	appName := randomTestCN("tf-int-app-weekly")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigWeekly(appName, []string{"Monday", "Thursday"}, "2025-01-01T02:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_days.0", "Monday"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_days.1", "Thursday"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_time", "2025-01-01T02:00:00Z"),
				),
			},
		},
	})
}

func TestIntKeyfactorApplicationResourceMonthlySchedule(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}
	appName := randomTestCN("tf-int-app-monthly")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigMonthly(appName, 1, "2025-01-01T04:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_monthly_day", "1"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_monthly_time", "2025-01-01T04:00:00Z"),
				),
			},
		},
	})
}

func TestIntKeyfactorApplicationResourceExactlyOnce(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}
	appName := randomTestCN("tf-int-app-once")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigExactlyOnce(appName, "2025-06-01T06:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_exactly_once_time", "2025-06-01T06:00:00Z"),
				),
			},
		},
	})
}

func TestIntKeyfactorApplicationResourceImmediate(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}
	appName := randomTestCN("tf-int-app-imm")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigImmediate(appName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_immediate", "true"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Acceptance tests for new schedule types
// ---------------------------------------------------------------------------

func TestAccKeyfactorApplicationResourceWeeklySchedule(t *testing.T) {
	appName := fmt.Sprintf("tf-acc-app-weekly-%d", time.Now().UnixNano()%1000000000)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigWeekly(appName, []string{"Monday", "Thursday"}, "2025-01-01T02:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_days.0", "Monday"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_days.1", "Thursday"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_time", "2025-01-01T02:00:00Z"),
				),
			},
			// Update days
			{
				Config: testAccApplicationConfigWeekly(appName, []string{"Wednesday", "Friday"}, "2025-01-01T02:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_days.0", "Wednesday"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_weekly_days.1", "Friday"),
				),
			},
		},
	})
}

func TestAccKeyfactorApplicationResourceMonthlySchedule(t *testing.T) {
	appName := fmt.Sprintf("tf-acc-app-monthly-%d", time.Now().UnixNano()%1000000000)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigMonthly(appName, 1, "2025-01-01T04:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_monthly_day", "1"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_monthly_time", "2025-01-01T04:00:00Z"),
				),
			},
			// Update day
			{
				Config: testAccApplicationConfigMonthly(appName, 15, "2025-01-01T04:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_monthly_day", "15"),
				),
			},
		},
	})
}

func TestAccKeyfactorApplicationResourceExactlyOnce(t *testing.T) {
	appName := fmt.Sprintf("tf-acc-app-once-%d", time.Now().UnixNano()%1000000000)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigExactlyOnce(appName, "2025-06-01T06:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_exactly_once_time", "2025-06-01T06:00:00Z"),
				),
			},
		},
	})
}

func TestAccKeyfactorApplicationResourceImmediate(t *testing.T) {
	appName := fmt.Sprintf("tf-acc-app-imm-%d", time.Now().UnixNano()%1000000000)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigImmediate(appName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttr("keyfactor_application.test", "schedule_immediate", "true"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccApplicationConfig(name string, overwriteSchedules bool, intervalMins int, dailyTime string) string {
	scheduleBlock := ""
	if intervalMins > 0 {
		scheduleBlock = fmt.Sprintf(`  schedule_interval_minutes = %d`, intervalMins)
	} else if dailyTime != "" {
		scheduleBlock = fmt.Sprintf(`  schedule_daily_time = "%s"`, dailyTime)
	}

	return fmt.Sprintf(`
resource "keyfactor_application" "test" {
  name                = "%s"
  overwrite_schedules = %v
  %s
}
`, name, overwriteSchedules, scheduleBlock)
}

func testAccApplicationConfigMinimal(name string) string {
	return fmt.Sprintf(`
resource "keyfactor_application" "test" {
  name = "%s"
}
`, name)
}

func testAccApplicationConfigImmediate(name string) string {
	return fmt.Sprintf(`
resource "keyfactor_application" "test" {
  name               = "%s"
  schedule_immediate = true
}
`, name)
}

func testAccApplicationConfigWeekly(name string, days []string, schedTime string) string {
	quoted := make([]string, len(days))
	for i, d := range days {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	return fmt.Sprintf(`
resource "keyfactor_application" "test" {
  name                 = "%s"
  schedule_weekly_days = [%s]
  schedule_weekly_time = "%s"
}
`, name, strings.Join(quoted, ", "), schedTime)
}

func testAccApplicationConfigMonthly(name string, day int, schedTime string) string {
	return fmt.Sprintf(`
resource "keyfactor_application" "test" {
  name                  = "%s"
  schedule_monthly_day  = %d
  schedule_monthly_time = "%s"
}
`, name, day, schedTime)
}

func testAccApplicationConfigExactlyOnce(name string, schedTime string) string {
	return fmt.Sprintf(`
resource "keyfactor_application" "test" {
  name                       = "%s"
  schedule_exactly_once_time = "%s"
}
`, name, schedTime)
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorApplicationResourceScheduleTypes tests weekly, monthly, and
// exactly_once schedule types using VCR cassettes (no lab required for replay).
func TestUnitKeyfactorApplicationResourceScheduleTypes(t *testing.T) {
	cassetteName := "application_resource_schedules"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var appName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		appName = fmt.Sprintf("tf-unit-app-sched-%d", time.Now().UnixNano()%1000000000)
		writeApplicationTestParams(cassettePath, applicationTestParams{AppName: appName})
	} else {
		params := readApplicationTestParams(cassettePath)
		appName = params.AppName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_application.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Weekly schedule
				Config: testAccApplicationConfigWeekly(appName+"-weekly", []string{"Monday", "Thursday"}, "2025-01-01T02:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "schedule_weekly_days.0", "Monday"),
					resource.TestCheckResourceAttr(resourceName, "schedule_weekly_days.1", "Thursday"),
					resource.TestCheckResourceAttr(resourceName, "schedule_weekly_time", "2025-01-01T02:00:00Z"),
				),
			},
			{
				// Update weekly days
				Config: testAccApplicationConfigWeekly(appName+"-weekly", []string{"Wednesday", "Friday"}, "2025-01-01T02:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "schedule_weekly_days.0", "Wednesday"),
					resource.TestCheckResourceAttr(resourceName, "schedule_weekly_days.1", "Friday"),
				),
			},
		},
	})
}

// TestUnitKeyfactorApplicationResourceMonthly tests monthly schedule using VCR cassettes.
func TestUnitKeyfactorApplicationResourceMonthly(t *testing.T) {
	cassetteName := "application_resource_monthly"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var appName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		appName = fmt.Sprintf("tf-unit-app-monthly-%d", time.Now().UnixNano()%1000000000)
		writeApplicationTestParams(cassettePath, applicationTestParams{AppName: appName})
	} else {
		params := readApplicationTestParams(cassettePath)
		appName = params.AppName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_application.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigMonthly(appName, 1, "2025-01-01T04:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "schedule_monthly_day", "1"),
					resource.TestCheckResourceAttr(resourceName, "schedule_monthly_time", "2025-01-01T04:00:00Z"),
				),
			},
			{
				// Update monthly day
				Config: testAccApplicationConfigMonthly(appName, 15, "2025-01-01T04:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "schedule_monthly_day", "15"),
				),
			},
		},
	})
}

// TestUnitKeyfactorApplicationResourceExactlyOnce tests exactly_once schedule using VCR cassettes.
func TestUnitKeyfactorApplicationResourceExactlyOnce(t *testing.T) {
	cassetteName := "application_resource_exactly_once"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var appName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		appName = fmt.Sprintf("tf-unit-app-once-%d", time.Now().UnixNano()%1000000000)
		writeApplicationTestParams(cassettePath, applicationTestParams{AppName: appName})
	} else {
		params := readApplicationTestParams(cassettePath)
		appName = params.AppName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_application.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfigExactlyOnce(appName, "2025-06-01T06:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "schedule_exactly_once_time", "2025-06-01T06:00:00Z"),
				),
			},
		},
	})
}

// TestUnitKeyfactorApplicationResource tests the keyfactor_application resource
// create/update lifecycle using VCR cassettes (no lab required for replay).
func TestUnitKeyfactorApplicationResource(t *testing.T) {
	cassetteName := "application_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var appName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		appName = fmt.Sprintf("tf-unit-app-%d", time.Now().UnixNano()%1000000000)
		writeApplicationTestParams(cassettePath, applicationTestParams{AppName: appName})
	} else {
		params := readApplicationTestParams(cassettePath)
		appName = params.AppName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_application.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create with interval schedule
				Config: testAccApplicationConfig(appName, false, 60, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					resource.TestCheckResourceAttr(resourceName, "overwrite_schedules", "false"),
					resource.TestCheckResourceAttr(resourceName, "schedule_interval_minutes", "60"),
				),
			},
			{
				// Update: shorten interval
				Config: testAccApplicationConfig(appName, false, 30, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					resource.TestCheckResourceAttr(resourceName, "schedule_interval_minutes", "30"),
				),
			},
			{
				// Update: switch to daily schedule
				Config: testAccApplicationConfig(appName, false, 0, "2023-11-25T23:30:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					resource.TestCheckResourceAttr(resourceName, "schedule_daily_time", "2023-11-25T23:30:00Z"),
				),
			},
		},
	})
}
