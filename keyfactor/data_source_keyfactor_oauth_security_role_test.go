package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorOAuthSecurityRoleDataSource tests the
// keyfactor_oauth_security_role data source using VCR cassettes.
func TestUnitKeyfactorOAuthSecurityRoleDataSource(t *testing.T) {
	cassetteName := "oauth_security_role_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var roleName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		roleName = fmt.Sprintf("tf-unit-oauth-role-ds-%d", time.Now().UnixNano()%1000000000)
		writeOAuthRoleRecordTestParams(cassettePath, oauthRoleRecordTestParams{RoleName: roleName})
	} else {
		params := readOAuthRoleRecordTestParams(cassettePath)
		roleName = params.RoleName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "keyfactor_permission_set" "global" {
	name = "Global"
}

resource "keyfactor_oauth_security_role" "unit_ds_setup" {
	name              = %q
	description       = "Unit test role for data source"
	permission_set_id = data.keyfactor_permission_set.global.id
	email_address     = "unit-test@example.com"
	permissions       = []
}

data "keyfactor_oauth_security_role" "test" {
	name = keyfactor_oauth_security_role.unit_ds_setup.name
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_role.test", "name", roleName),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "description"),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "permission_set_id"),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_role.test", "email_address", "unit-test@example.com"),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_role.test", "permissions.#"),
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
