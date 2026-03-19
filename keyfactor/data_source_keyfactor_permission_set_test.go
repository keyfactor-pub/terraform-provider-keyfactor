package keyfactor

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorPermissionSetDataSource tests the keyfactor_permission_set
// data source using VCR cassettes. Reads the well-known "Global" permission set.
func TestUnitKeyfactorPermissionSetDataSource(t *testing.T) {
	cassetteName := "permission_set_data_source"
	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dsName := "data.keyfactor_permission_set.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceKeyfactorPermissionSet("keyfactor_permission_set", "Global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "name", "Global"),
					resource.TestCheckResourceAttrWith(dsName, "permissions.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected Global permission set to have at least one permission, got 0")
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestAccKeyfactorPermissionSetDataSource(t *testing.T) {
	var resourceType = "keyfactor_permission_set"
	var resourceName = fmt.Sprintf("data.%s.test", resourceType)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorPermissionSet(resourceType, "Global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "permissions.#"),
					resource.TestCheckResourceAttr(resourceName, "name", "Global"),
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorPermissionSet(resourceName string, permissionSetName string) string {
	output := fmt.Sprintf(`
	data "%s" "test" {
		name = "%s"
	}
	`, resourceName, permissionSetName)
	return output
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorPermissionSetDataSource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceKeyfactorPermissionSet("keyfactor_permission_set", "Global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_permission_set.test", "id"),
					resource.TestCheckResourceAttrSet("data.keyfactor_permission_set.test", "permissions.#"),
					resource.TestMatchResourceAttr("data.keyfactor_permission_set.test", "permissions.#", regexp.MustCompile(`^[1-9][0-9]*$`)),
					resource.TestCheckResourceAttr("data.keyfactor_permission_set.test", "name", "Global"),
				),
			},
		},
	})
}
