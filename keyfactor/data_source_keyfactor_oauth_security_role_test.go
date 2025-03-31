package keyfactor

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorOAuthSecurityRoleDataSource(t *testing.T) {
	var resourceType = "keyfactor_oauth_security_role"
	var resourceName = fmt.Sprintf("data.%s.test", resourceType)

	securityRoleName := os.Getenv("KEYFACTOR_OAUTH_SECURITY_ROLE_NAME")

	if securityRoleName == "" {
		t.Skip("Skipping test due to missing environment variables: KEYFACTOR_OAUTH_SECURITY_ROLE_NAME is required")
	}

	// In order for test to pass, security role MUST have:
	// - Email set (not empty)
	// - At least one permission associated with it
	// - At least one claim associated with it
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
					resource.TestCheckResourceAttrSet(resourceName, "claims.#"),
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
