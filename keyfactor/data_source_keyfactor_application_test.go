package keyfactor

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Acceptance tests (TF_ACC=1, reads env vars for config)
// ---------------------------------------------------------------------------

// TestAccKeyfactorApplicationDataSource tests reading a keyfactor_application data source.
// It first creates an application resource and then reads it back via the data source.
func TestAccKeyfactorApplicationDataSource(t *testing.T) {
	baseName := os.Getenv("KEYFACTOR_APPLICATION_NAME")
	if baseName == "" {
		baseName = "tf-acc-app-ds"
	}
	appName := fmt.Sprintf("%s-%d", baseName, time.Now().UnixNano()%1000000000)
	resourceName := "keyfactor_application.test"
	dataSourceName := "data.keyfactor_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create resource then read it back via data source by name
			{
				Config: testAccApplicationConfig(appName, false, 60, "") + "\n" +
					testAccApplicationDataSourceByName(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Resource checks
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", appName),
					// Data source checks — read back by name
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "name", appName),
					resource.TestCheckResourceAttrSet(dataSourceName, "overwrite_schedules"),
					resource.TestCheckResourceAttrSet(dataSourceName, "certificate_store_ids.#"),
				),
			},
		},
	})
}

// TestAccKeyfactorApplicationDataSourceByID tests reading an application by integer ID.
func TestAccKeyfactorApplicationDataSourceByID(t *testing.T) {
	baseName := os.Getenv("KEYFACTOR_APPLICATION_NAME")
	if baseName == "" {
		baseName = "tf-acc-app-ds-id"
	}
	appName := fmt.Sprintf("%s-%d", baseName, time.Now().UnixNano()%1000000000)
	resourceName := "keyfactor_application.test"
	dataSourceName := "data.keyfactor_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationConfig(appName, false, 0, "") + "\n" +
					testAccApplicationDataSourceByID(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "name", appName),
					resource.TestCheckResourceAttrSet(dataSourceName, "certificate_store_ids.#"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorApplicationDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	appName := randomTestCN("tf-int-app-ds")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create an application resource then read it back via data source by name
				Config: testAccApplicationConfig(appName, false, 60, "") + "\n" +
					testAccApplicationDataSourceByName("keyfactor_application.test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_application.test", "id"),
					// Data source checks
					resource.TestCheckResourceAttrSet("data.keyfactor_application.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_application.test", "name", appName),
					resource.TestCheckResourceAttrSet("data.keyfactor_application.test", "certificate_store_ids.#"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

// testAccApplicationDataSourceByName reads an application by name, referencing the resource.
func testAccApplicationDataSourceByName(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_application" "test" {
  identifier = %s.name
}
`, resourceRef)
}

// testAccApplicationDataSourceByID reads an application by integer ID, referencing the resource.
func testAccApplicationDataSourceByID(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_application" "test" {
  identifier = %s.id
}
`, resourceRef)
}
