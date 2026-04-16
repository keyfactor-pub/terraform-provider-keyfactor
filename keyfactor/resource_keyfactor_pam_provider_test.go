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
			{
				// Import by integer ID — param_values are write-only and cannot be recovered
				ResourceName:            "keyfactor_pam_provider.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"param_values"},
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
			{
				// Import by integer ID
				ResourceName:      "keyfactor_pam_provider.test",
				ImportState:       true,
				ImportStateVerify: true,
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

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorPAMProviderResource tests the keyfactor_pam_provider resource
// create/update lifecycle using VCR cassettes (no lab required for replay).
// The config also creates a keyfactor_pam_provider_type inline.
func TestUnitKeyfactorPAMProviderResource(t *testing.T) {
	cassetteName := "pam_provider_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var typeName, provName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		typeName = fmt.Sprintf("tf-unit-pamtype-%d", time.Now().UnixNano()%1000000000)
		provName = fmt.Sprintf("tf-unit-pam-%d", time.Now().UnixNano()%1000000000)
		writePAMProviderTestParams(cassettePath, pamProviderTestParams{TypeName: typeName, ProvName: provName})
	} else {
		params := readPAMProviderTestParams(cassettePath)
		typeName = params.TypeName
		provName = params.ProvName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_pam_provider.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create PAM provider type + provider with two param values
				Config: testAccPAMProviderConfig(typeName, provName, "https://pam.example.com", "secret123"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", provName),
					resource.TestCheckResourceAttrSet(resourceName, "provider_type_id"),
					resource.TestCheckResourceAttr(resourceName, "param_values.#", "2"),
				),
			},
			{
				// Update: rename provider and change param values
				Config: testAccPAMProviderConfig(typeName, provName+"-updated", "https://pam2.example.com", "newsecret456"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", provName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "param_values.#", "2"),
				),
			},
		},
	})
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
