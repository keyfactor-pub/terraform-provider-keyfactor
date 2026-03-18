package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorOAuthSecurityRoleDataSource(t *testing.T) {
	var resourceType = "keyfactor_oauth_security_role"
	var resourceName = fmt.Sprintf("data.%s.test", resourceType)

	securityRoleName := getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_ROLE_NAME")

	// In order for test to pass, security role MUST have:
	// - Email set (not empty)
	// - At least one permission associated with it
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorOAuthSecurityRole(resourceType, securityRoleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "description"),
					resource.TestCheckResourceAttrSet(resourceName, "permission_set_id"),
					resource.TestCheckResourceAttrSet(resourceName, "permissions.#"),
					resource.TestCheckResourceAttrSet(resourceName, "email_address"),
					resource.TestCheckResourceAttr(resourceName, "name", securityRoleName),
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorOAuthSecurityRole(resourceName string, roleName string) string {
	output := fmt.Sprintf(`
	data "%s" "test" {
		name = "%s"
	}
	`, resourceName, roleName)
	return output
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorOAuthSecurityRoleDataSource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	roleName := acctest.RandomWithPrefix("tf-int-oauth-role-ds")

	// Create a role first, then read it back via data source
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "keyfactor_permission_set" "global" {
	name = "Global"
}

resource "keyfactor_oauth_security_role" "int_ds_setup" {
	name              = "%s"
	description       = "Integration test role for data source"
	permission_set_id = data.keyfactor_permission_set.global.id
	email_address     = "test@example.com"
	permissions       = []
}

data "keyfactor_oauth_security_role" "test" {
	name = keyfactor_oauth_security_role.int_ds_setup.name
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_role.test", "name", roleName),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "description"),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "permission_set_id"),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "email_address"),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "permissions.#"),
				),
			},
		},
	})
}
