package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorPAMProviderResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pamtype")
	provName := randomTestCN("tf-int-pamprov")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a PAM provider type + provider with param values
				Config: testAccPAMProviderConfig(typeName, provName, "https://pam.example.com", "secret123"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider.test", "name", provName),
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider.test", "provider_type_id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider.test", "param_values.#", "2"),
				),
			},
			{
				// Update: change provider name and param values
				Config: testAccPAMProviderConfig(typeName, provName+"-updated", "https://pam2.example.com", "newsecret456"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider.test", "name", provName+"-updated"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider.test", "param_values.#", "2"),
				),
			},
		},
	})
}

func TestIntKeyfactorPAMProviderResourceMinimal(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pamtype-min")
	provName := randomTestCN("tf-int-pamprov-min")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a PAM provider with no param values
				Config: testAccPAMProviderConfigMinimal(typeName, provName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider.test", "name", provName),
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider.test", "provider_type_id"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccPAMProviderConfig(typeName, provName, hostValue, secretValue string) string {
	return fmt.Sprintf(`
resource "keyfactor_pam_provider_type" "test" {
  name = "%s"

  parameters = [
    {
      name           = "Host"
      display_name   = "PAM Host"
      data_type      = 1
      instance_level = false
    },
    {
      name           = "ApiKey"
      display_name   = "PAM API Key"
      data_type      = 2
      instance_level = false
    },
  ]
}

resource "keyfactor_pam_provider" "test" {
  name             = "%s"
  provider_type_id = keyfactor_pam_provider_type.test.id

  param_values = [
    {
      param_id = keyfactor_pam_provider_type.test.parameters[0].id
      name     = keyfactor_pam_provider_type.test.parameters[0].name
      value    = "%s"
    },
    {
      param_id = keyfactor_pam_provider_type.test.parameters[1].id
      name     = keyfactor_pam_provider_type.test.parameters[1].name
      value    = "%s"
    },
  ]
}
`, typeName, provName, hostValue, secretValue)
}

func testAccPAMProviderConfigMinimal(typeName, provName string) string {
	return fmt.Sprintf(`
resource "keyfactor_pam_provider_type" "test_type" {
  name = "%s"
}

resource "keyfactor_pam_provider" "test" {
  name             = "%s"
  provider_type_id = keyfactor_pam_provider_type.test_type.id
}
`, typeName, provName)
}
