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

func TestIntKeyfactorPAMProviderDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pamtype-ds")
	provName := randomTestCN("tf-int-pamprov-ds")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a type + provider, then read back via data source by name
				Config: testAccPAMProviderConfigMinimal(typeName, provName) + "\n" +
					testAccPAMProviderDataSourceByName("keyfactor_pam_provider.test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Resource checks
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider.test", "name", provName),
					// Data source checks
					resource.TestCheckResourceAttrSet("data.keyfactor_pam_provider.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_pam_provider.test", "name", provName),
					resource.TestCheckResourceAttrSet("data.keyfactor_pam_provider.test", "provider_type_id"),
					resource.TestCheckResourceAttrSet("data.keyfactor_pam_provider.test", "provider_type_name"),
				),
			},
		},
	})
}

func TestIntKeyfactorPAMProviderDataSourceByID(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pamtype-ds-id")
	provName := randomTestCN("tf-int-pamprov-ds-id")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a type + provider, then read back via data source by integer ID
				Config: testAccPAMProviderConfigMinimal(typeName, provName) + "\n" +
					testAccPAMProviderDataSourceByID("keyfactor_pam_provider.test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_pam_provider.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_pam_provider.test", "name", provName),
					resource.TestCheckResourceAttrSet("data.keyfactor_pam_provider.test", "provider_type_id"),
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

// TestUnitKeyfactorPAMProviderDataSource tests the keyfactor_pam_provider data
// source using VCR cassettes (no lab required for replay). Covers lookup by
// name and by integer ID.
func TestUnitKeyfactorPAMProviderDataSource(t *testing.T) {
	cassetteName := "pam_provider_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var typeName, provName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		typeName = fmt.Sprintf("tf-unit-pamtype-ds-%d", time.Now().UnixNano()%1000000000)
		provName = fmt.Sprintf("tf-unit-pam-ds-%d", time.Now().UnixNano()%1000000000)
		writePAMProviderTestParams(cassettePath, pamProviderTestParams{TypeName: typeName, ProvName: provName})
	} else {
		params := readPAMProviderTestParams(cassettePath)
		typeName = params.TypeName
		provName = params.ProvName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_pam_provider.test"
	dataSourceName := "data.keyfactor_pam_provider.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create type + provider, read back by name
				Config: testAccPAMProviderConfigMinimal(typeName, provName) + "\n" +
					testAccPAMProviderDataSourceByName(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", provName),
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "name", provName),
					resource.TestCheckResourceAttrSet(dataSourceName, "provider_type_id"),
					resource.TestCheckResourceAttr(dataSourceName, "provider_type_name", typeName),
				),
			},
			{
				// Read the same provider by integer ID
				Config: testAccPAMProviderConfigMinimal(typeName, provName) + "\n" +
					testAccPAMProviderDataSourceByID(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "name", provName),
					resource.TestCheckResourceAttrSet(dataSourceName, "provider_type_id"),
					resource.TestCheckResourceAttr(dataSourceName, "provider_type_name", typeName),
				),
			},
		},
	})
}

func testAccPAMProviderDataSourceByName(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_pam_provider" "test" {
  identifier = %s.name
}
`, resourceRef)
}

func testAccPAMProviderDataSourceByID(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_pam_provider" "test" {
  identifier = %s.id
}
`, resourceRef)
}
