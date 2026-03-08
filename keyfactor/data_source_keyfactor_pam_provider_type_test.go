package keyfactor

import (
	"fmt"
	"testing"

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
