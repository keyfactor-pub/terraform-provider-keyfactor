package keyfactor

import (
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAccKeyfactorSecurityIdentityBasic(t *testing.T) {
	skipIdentity := testAccKeyfactorSecurityIdentityCheckSkip()
	if skipIdentity {
		t.Skip("Skipping security identity tests (KEYFACTOR_SKIP_IDENTITY_TESTS=true)")
	}

	accountName, roleId1, roleId2 := testAccKeyfactorSecurityIdentityGetConfig(t)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_security_identity.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorSecurityIdentityDestroy,
		Steps: []resource.TestStep{
			{
				// Test basic creation of a Keyfactor identity
				Config: testAccCheckKeyfactorSecurityIdentityBasic(accountName),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityIdentityExists("keyfactor_security_identity.test"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.account_name"), // todo figure out how to fix escape character problems
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.id"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.identity_type"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.valid"),
				),
			},
			{
				// Test adding a role to a Keyfactor identity
				Config: testAccCheckKeyfactorSecurityIdentityBasicModified(accountName, roleId1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityIdentityExists("keyfactor_security_identity.test"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.account_name"), // todo figure out how to fix escape character problems
					resource.TestCheckResourceAttr("keyfactor_security_identity.test", "security_identity.0.roles.0", roleId1),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.id"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.identity_type"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.valid"),
				),
			},
			{
				// Test changing the role attached to an identity
				Config: testAccCheckKeyfactorSecurityIdentityBasicModified(accountName, roleId2),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityIdentityExists("keyfactor_security_identity.test"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.account_name"), // todo figure out how to fix escape character problems
					resource.TestCheckResourceAttr("keyfactor_security_identity.test", "security_identity.0.roles.0", roleId2),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.id"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.identity_type"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.valid"),
				),
			},
			{
				// Test removing the role attached to an identity
				Config: testAccCheckKeyfactorSecurityIdentityBasic(accountName),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorSecurityIdentityExists("keyfactor_security_identity.test"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.account_name"), // todo figure out how to fix escape character problems
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.id"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.identity_type"),
					resource.TestCheckResourceAttrSet("keyfactor_security_identity.test", "security_identity.0.valid"),
				),
			},
		},
	})
}

func testAccCheckKeyfactorSecurityIdentityExists(name string) resource.TestCheckFunc {
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

		identities, err := conn.GetSecurityIdentities()
		if err != nil {
			return err
		}

		var identityContext keyfactor.GetSecurityIdentityResponse

		// Search the returned list of identies for the ID of the resource
		for _, identity := range identities {
			if identity.Id == id {
				identityContext = identity
			}
		}

		if identityContext.Valid == true && identityContext.AccountName != "" {
			return nil
		}

		return fmt.Errorf("identity does not exist in kefactor")
	}
}

func testAccKeyfactorSecurityIdentityGetConfig(t *testing.T) (string, string, string) {
	var accountName string
	var roleId1 string
	var roleId2 string
	if accountName = os.Getenv("KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME"); accountName == "" {
		t.Log("Note: Terraform Security Identity tests attempt to create a new identity based on an AD user or " +
			"group. Please create a new user/group in AD for testing if one isn't already created.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_IDENTITY_TESTS to 'true' to skip Security Identity " +
			"resource acceptance tests")
		t.Fatal("KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME must be set to perform Security Identity acceptance test. " +
			"(EX '<DOMAIN>\\\\<user or group name>')")
	}
	if roleId1 = os.Getenv("KEYFACTOR_SECURITY_IDENTITY_ROLEID1"); roleId1 == "" {
		t.Log("Note: Terraform Security Identity tests attempt to add an identity to a Keyfactor security role.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_IDENTITY_TESTS to 'true' to skip Security Identity " +
			"resource acceptance tests")
		t.Fatal("KEYFACTOR_SECURITY_IDENTITY_ROLEID1 must be set to perform Security Identity acceptance test. " +
			"(EX '14'")
	}
	if roleId2 = os.Getenv("KEYFACTOR_SECURITY_IDENTITY_ROLEID2"); roleId2 == "" {
		t.Log("Note: Terraform Security Identity tests attempt to add an identity to a Keyfactor security role.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_IDENTITY_TESTS to 'true' to skip Security Identity " +
			"resource acceptance tests")
		t.Fatal("KEYFACTOR_SECURITY_IDENTITY_ROLEID2 must be set to perform Security Identity acceptance test. " +
			"(EX '14'")
	}
	return accountName, roleId1, roleId2
}

func testAccKeyfactorSecurityIdentityCheckSkip() bool {
	skipIdentityTests := false
	if temp := os.Getenv("KEYFACTOR_SKIP_IDENTITY_TESTS"); temp != "" {
		if strings.ToLower(temp) == "true" {
			skipIdentityTests = true
		}
	}
	return skipIdentityTests
}

func testAccCheckKeyfactorSecurityIdentityDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "keyfactor_security_identity" {
			continue
		}

		id, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}

		// Pull the provider metadata interface out of the testAccProvider provider
		conn := testAccProvider.Meta().(*keyfactor.Client)

		// conn is a configured Keyfactor Go Client object, get all Keyfactor security identities
		identities, err := conn.GetSecurityIdentities()
		if err != nil {
			return err
		}

		// Search the returned list of identies for the ID of the resource
		for _, identity := range identities {
			if identity.Id == id {
				return fmt.Errorf("resource still exists, ID: %d", id)
			}
		}
		// If we get here, the identity doesn't exist in Keyfactor
	}
	return nil
}

func testAccCheckKeyfactorSecurityIdentityBasic(accountName string) string {
	return fmt.Sprintf(`
	resource "keyfactor_security_identity" "test" {
		security_identity {
			account_name = "%s"
		}
	}
	`, accountName)
}

func testAccCheckKeyfactorSecurityIdentityBasicModified(accountName string, role string) string {
	return fmt.Sprintf(`
	resource "keyfactor_security_identity" "test" {
		security_identity {
			account_name = "%s"
			roles        = [%s]
		}
	}
	`, accountName, role)
}
