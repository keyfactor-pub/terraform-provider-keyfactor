package keyfactor

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

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
