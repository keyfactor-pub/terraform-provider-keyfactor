package keyfactor

import (
	"fmt"
	"testing"

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
