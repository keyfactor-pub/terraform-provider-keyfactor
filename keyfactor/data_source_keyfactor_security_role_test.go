package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorSecurityRoleDataSource tests the keyfactor_role data source
// using VCR cassettes. Reads the well-known "Administrator" role.
func TestUnitKeyfactorSecurityRoleDataSource(t *testing.T) {
	cassetteName := "security_role_data_source"
	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dataSourceName := "data.keyfactor_role.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceKeyfactorSecurityRoleBasic("Administrator"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttr(dataSourceName, "name", "Administrator"),
					resource.TestCheckResourceAttrSet(dataSourceName, "description"),
					resource.TestCheckResourceAttrSet(dataSourceName, "permissions.#"),
				),
			},
		},
	})
}

func TestAccKeyfactorSecurityRoleDataSource(t *testing.T) {
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_role")
	var rName = "Administrator"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorSecurityRoleBasic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "1"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttrSet(resourceName, "description"),
					resource.TestCheckResourceAttrSet(resourceName, "permissions.#"),
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorSecurityRoleBasic(resourceName string) string {
	return fmt.Sprintf(`
	data "keyfactor_role" "test" {
		name = "%s"
	}
	`, resourceName)
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorSecurityRoleDataSource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceKeyfactorSecurityRoleBasic("Administrator"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_role.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_role.test", "name", "Administrator"),
					resource.TestCheckResourceAttrSet("data.keyfactor_role.test", "description"),
					resource.TestCheckResourceAttrSet("data.keyfactor_role.test", "permissions.#"),
				),
			},
		},
	})
}
