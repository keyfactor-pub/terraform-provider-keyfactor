package keyfactor

import (
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAccKeyfactorSecurityRoleBasic(t *testing.T) {
	skipRole := testAccKeyfactorSecurityRoleCheckSkip()
	if skipRole {
		t.Skip("Skipping security role tests (KEYFACTOR_SKIP_ROLE_TESTS=true)")
	}

	accountName := testAccKeyfactorSecurityRoleGetConfig(t)
	roleName := "TerraformRole_" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	description := "Terraform acceptance test check description - " + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	permission1a := "Monitoring:Read"
	permission1b := "Monitoring:Modify"
	permission2a := "SecuritySettings:Read"
	permission2b := "SecuritySettings:Modify"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_security_role.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorSecurityRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorSecurityRoleBasic(roleName, description),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityRoleExists("keyfactor_security_role.test"),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "description", description),
					// Check computed values
					// jk there aren't any computed values for the basic test
				),
			},
			{
				// Add some permissions
				Config: testAccCheckKeyfactorSecurityRoleModified(roleName, description, accountName, permission1a, permission2a),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityRoleExists("keyfactor_security_role.test"),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "description", description),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "identities.#", "1"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.account_name"), // todo figure out how to fix escape character problems
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "permissions.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "permissions.0", permission1a),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "permissions.1", permission2a),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.id"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.identity_type"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.sid"),
				),
			},
			{
				// Change the permissions
				Config: testAccCheckKeyfactorSecurityRoleModified(roleName, description, accountName, permission1b, permission2b),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityRoleExists("keyfactor_security_role.test"),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "description", description),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "identities.#", "1"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.account_name"), // todo figure out how to fix escape character problems
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "permissions.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "permissions.0", permission1b),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "permissions.1", permission2b),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.id"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.identity_type"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities.0.sid"),
				),
			},
			{
				// Delete the permissions and remove the identity
				Config: testAccCheckKeyfactorSecurityRoleBasic(roleName, description),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityRoleExists("keyfactor_security_role.test"),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "description", description),
					// Check computed values
					// jk there aren't any computed values for the basic test
				),
			},
		},
	})
}

func testAccKeyfactorSecurityRoleCheckSkip() bool {
	skipRoleTests := false
	if temp := os.Getenv("KEYFACTOR_SKIP_ROLE_TESTS"); temp != "" {
		if strings.ToLower(temp) == "true" {
			skipRoleTests = true
		}
	}
	return skipRoleTests
}

func testAccCheckKeyfactorSecurityRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {

		if rs.Type != "keyfactor_security_role" {
			continue
		}

		id, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}

		// Pull the provider metadata interface out of the testAccProvider provider
		conn := testAccProvider.Meta().(*keyfactor.Client)

		// conn is a configured Keyfactor Go Client object, pull down the role id
		_, err = conn.GetSecurityRole(id)
		// If GetSecurityRole doesn't fail, resource still exists
		if err == nil {
			return fmt.Errorf("resource still exists, ID: %s", rs.Primary.ID)
		}

		// If we get here, the identity doesn't exist in Keyfactor
	}
	return nil
}

func testAccKeyfactorSecurityRoleGetConfig(t *testing.T) string {
	var accountName string
	if accountName = os.Getenv("KEYFACTOR_SECURITY_ROLE_IDENTITY_ACCOUNTNAME"); accountName == "" {
		t.Log("Note: Terraform Security Role tests attempt to add previously created identities to a new role. " +
			"Create a new security identity in Keyfactor, and set this environment to test the role resource.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_IDENTITY_TESTS to 'true' to skip Security Identity " +
			"resource acceptance tests")
		t.Fatal("KEYFACTOR_SECURITY_ROLE_IDENTITY_ACCOUNTNAME must be set to perform Security Identity acceptance test. " +
			"(EX '<DOMAIN>\\\\<user or group name>')")
	}
	return accountName
}

func testAccCheckKeyfactorSecurityRoleExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("no Identity ID set")
		}

		conn := testAccProvider.Meta().(*keyfactor.Client)

		id, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}

		role, err := conn.GetSecurityRole(id)
		if err != nil {
			return err
		}

		if role.Name != "" && role.Description != "" {
			return nil
		}

		// If we get to this point, role does not exist.
		return fmt.Errorf("identity does not exist in kefactor")
	}
}

func testAccCheckKeyfactorSecurityRoleBasic(roleName string, roleDesc string) string {
	return fmt.Sprintf(`
	resource "keyfactor_security_role" "test" {
		role_name = "%s"
		description = "%s"
	}
	`, roleName, roleDesc)
}

func testAccCheckKeyfactorSecurityRoleModified(roleName string, roleDesc string, accountName string, permission1 string, permission2 string) string {
	return fmt.Sprintf(`
	resource "keyfactor_security_role" "test" {
		role_name = "%s"
		description = "%s"
		identities {
			account_name = "%s"
		}
		permissions = ["%s", "%s"]
	}
	`, roleName, roleDesc, accountName, permission1, permission2)
}
