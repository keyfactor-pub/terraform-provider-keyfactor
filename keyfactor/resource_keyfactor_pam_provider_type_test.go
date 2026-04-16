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

func TestIntKeyfactorPAMProviderTypeResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pam-type")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a PAM provider type with parameters
				Config: testAccPAMProviderTypeConfig(typeName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider_type.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "name", typeName),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "parameters.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "parameters.0.name", "Host"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "parameters.0.data_type", "1"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "parameters.1.name", "ApiKey"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "parameters.1.data_type", "2"),
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider_type.test", "parameters.0.id"),
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider_type.test", "parameters.1.id"),
				),
			},
			{
				// Import by GUID
				ResourceName:      "keyfactor_pam_provider_type.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestIntKeyfactorPAMProviderTypeResourceMinimal(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	typeName := randomTestCN("tf-int-pam-type-min")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create a PAM provider type with no parameters
				Config: testAccPAMProviderTypeConfigMinimal(typeName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_pam_provider_type.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "name", typeName),
					resource.TestCheckResourceAttr("keyfactor_pam_provider_type.test", "parameters.#", "0"),
				),
			},
			{
				// Import by GUID
				ResourceName:      "keyfactor_pam_provider_type.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccPAMProviderTypeConfig(name string) string {
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
`, name)
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorPAMProviderTypeResource tests the keyfactor_pam_provider_type
// resource create lifecycle using VCR cassettes (no lab required for replay).
// All user-settable attributes have RequiresReplace, so a single create step
// exercises the full lifecycle (create + refresh + destroy).
func TestUnitKeyfactorPAMProviderTypeResource(t *testing.T) {
	cassetteName := "pam_provider_type_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var typeName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		typeName = fmt.Sprintf("tf-unit-pamtype-%d", time.Now().UnixNano()%1000000000)
		writePAMProviderTypeTestParams(cassettePath, pamProviderTypeTestParams{TypeName: typeName})
	} else {
		params := readPAMProviderTypeTestParams(cassettePath)
		typeName = params.TypeName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_pam_provider_type.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create provider type with two parameters (string + secret)
				Config: testAccPAMProviderTypeConfig(typeName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", typeName),
					resource.TestCheckResourceAttr(resourceName, "parameters.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.name", "Host"),
					resource.TestCheckResourceAttr(resourceName, "parameters.0.data_type", "1"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.name", "ApiKey"),
					resource.TestCheckResourceAttr(resourceName, "parameters.1.data_type", "2"),
					resource.TestCheckResourceAttrSet(resourceName, "parameters.0.id"),
					resource.TestCheckResourceAttrSet(resourceName, "parameters.1.id"),
				),
			},
		},
	})
}

func testAccPAMProviderTypeConfigMinimal(name string) string {
	return fmt.Sprintf(`
resource "keyfactor_pam_provider_type" "test" {
  name = "%s"
}
`, name)
}
