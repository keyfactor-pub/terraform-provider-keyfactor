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
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorPAMProviderTypeDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pam-type-ds")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a type then read it back via data source by name
				Config: testAccPAMProviderTypeConfig(typeName) + "\n" +
					testAccPAMProviderTypeDataSourceByName("keyfactor_pam_provider_type.test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Resource checks
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider_type.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "name", typeName),
					// Data source checks
					resource.TestCheckResourceAttrSet("data.keyfactor_pam_provider_type.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_pam_provider_type.test", "name", typeName),
					resource.TestCheckResourceAttr("data.keyfactor_pam_provider_type.test", "parameters.#", "2"),
				),
			},
		},
	})
}

func TestIntKeyfactorPAMProviderTypeDataSourceByGUID(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pam-type-ds-guid")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a type then read it back via data source by GUID
				Config: testAccPAMProviderTypeConfig(typeName) + "\n" +
					testAccPAMProviderTypeDataSourceByGUID("keyfactor_pam_provider_type.test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_pam_provider_type.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_pam_provider_type.test", "name", typeName),
					resource.TestCheckResourceAttr("data.keyfactor_pam_provider_type.test", "parameters.#", "2"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorPAMProviderTypeDataSource tests the keyfactor_pam_provider_type
// data source using VCR cassettes (no lab required for replay). Covers lookup
// by name and by GUID.
func TestUnitKeyfactorPAMProviderTypeDataSource(t *testing.T) {
	cassetteName := "pam_provider_type_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var typeName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		typeName = fmt.Sprintf("tf-unit-pamtype-ds-%d", time.Now().UnixNano()%1000000000)
		writePAMProviderTypeTestParams(cassettePath, pamProviderTypeTestParams{TypeName: typeName})
	} else {
		params := readPAMProviderTypeTestParams(cassettePath)
		typeName = params.TypeName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_pam_provider_type.test"
	dataSourceName := "data.keyfactor_pam_provider_type.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create type, read back by name
				Config: testAccPAMProviderTypeConfig(typeName) + "\n" +
					testAccPAMProviderTypeDataSourceByName(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", typeName),
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "name", typeName),
					resource.TestCheckResourceAttr(dataSourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(dataSourceName, "parameters.0.name", "Host"),
					resource.TestCheckResourceAttr(dataSourceName, "parameters.1.name", "ApiKey"),
				),
			},
			{
				// Read the same type by GUID
				Config: testAccPAMProviderTypeConfig(typeName) + "\n" +
					testAccPAMProviderTypeDataSourceByGUID(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "name", typeName),
					resource.TestCheckResourceAttr(dataSourceName, "parameters.#", "2"),
				),
			},
		},
	})
}

func testAccPAMProviderTypeDataSourceByName(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_pam_provider_type" "test" {
  identifier = %s.name
}
`, resourceRef)
}

func testAccPAMProviderTypeDataSourceByGUID(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_pam_provider_type" "test" {
  identifier = %s.id
}
`, resourceRef)
}
