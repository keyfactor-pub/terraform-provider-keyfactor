package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
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
				// Create without schedule
				Config: testAccApplicationConfigMinimal(appName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_application.test", "name", appName),
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

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

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
