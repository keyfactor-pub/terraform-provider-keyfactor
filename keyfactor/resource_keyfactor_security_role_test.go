package keyfactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type roleTestCase struct {
	name           string
	description    string
	permissions    []string
	permissionsStr string
	resourceName   string
}

func TestAccKeyfactorRoleResource(t *testing.T) {

	r := roleTestCase{
		name:        os.Getenv("KEYFACTOR_SECURITY_ROLE_NAME"),
		description: "Role used for a Terraform.",
		permissions: []string{
			"AdminPortal:Read",
			"API:Read",
		},
		resourceName: "keyfactor_role.terraform_test",
	}
	pStr, _ := json.Marshal(r.permissions)
	r.permissionsStr = string(pStr)

	// Update to multiple roles test
	r2 := r
	additionalPermissions := []string{
		"Certificates:Read",
		"Certificates:EditMetadata",
		"Certificates:Import",
		"Certificates:Recover",
		"Certificates:Revoke",
		"Certificates:Delete",
		"Certificates:ImportPrivateKey",
		"CertificateCollections:Modify",
		"PkiManagement:Read",
		"PkiManagement:Modify",
		"CertificateStoreManagement:Read",
		"CertificateStoreManagement:Modify",
		"CertificateStoreManagement:Schedule",
		"CertificateEnrollment:EnrollPFX",
		"CertificateEnrollment:EnrollCSR",
		"CertificateEnrollment:CsrGeneration",
		"CertificateEnrollment:PendingCsr",
	}
	r2.permissions = append(r2.permissions, additionalPermissions...)
	r2Str, _ := json.Marshal(r2.permissions)
	r2.permissionsStr = string(r2Str)

	// Update to no roles test
	r3 := r2
	r3.permissions = []string{}
	r3Str, _ := json.Marshal(r3.permissions)
	r3.permissionsStr = string(r3Str)

	// Testing Role
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorRoleResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "name"),          // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "permissions.0"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "permissions.1"), // TODO: Check specific value

				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Update and Read testing
			{
				Config: testAccKeyfactorRoleResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r2.resourceName, "name"),          // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.0"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.1"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.3"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.4"), // TODO: Check specific value
				),
			},
			{
				Config: testAccKeyfactorRoleResourceConfig(r3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r3.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r3.resourceName, "name"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r3.resourceName, "permissions.#"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorSecurityRoleResource tests the keyfactor_role resource
// create/update lifecycle using VCR cassettes (no lab required for replay).
func TestUnitKeyfactorSecurityRoleResource(t *testing.T) {
	cassetteName := "security_role_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var roleName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		roleName = fmt.Sprintf("tf-unit-role-%d", time.Now().UnixNano()%1000000000)
		writeSecurityRoleTestParams(cassettePath, securityRoleTestParams{RoleName: roleName})
	} else {
		params := readSecurityRoleTestParams(cassettePath)
		roleName = params.RoleName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_role.unit_test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "unit_test" {
	name        = %q
	description = "Unit test role"
	permissions = []
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "description", "Unit test role"),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "0"),
				),
			},
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "unit_test" {
	name        = %q
	description = "Unit test role updated"
	permissions = distinct(sort(["Certificates:Read", "Certificates:EditMetadata"]))
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "description", "Unit test role updated"),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "permissions.0", "Certificates:EditMetadata"),
					resource.TestCheckResourceAttr(resourceName, "permissions.1", "Certificates:Read"),
				),
			},
		},
	})
}

func testAccKeyfactorRoleResourceConfig(t roleTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_role" "terraform_test" {
	name = "%s"
	description  = "%s"
	permissions  = distinct(sort(%s))
}
`, t.name, t.description, t.permissionsStr)
	return output
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorRoleResource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	roleName := fmt.Sprintf("tf-int-test-%d", time.Now().UnixNano())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with no permissions
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "int_test" {
	name        = "%s"
	description = "Integration test role"
	permissions = []
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_role.int_test", "id"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "name", roleName),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "description", "Integration test role"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "permissions.#", "0"),
				),
			},
			// Update: add permissions
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "int_test" {
	name        = "%s"
	description = "Integration test role updated"
	permissions = distinct(sort(["Certificates:Read", "Certificates:EditMetadata"]))
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_role.int_test", "id"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "description", "Integration test role updated"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "permissions.#", "2"),
				),
			},
		},
	})
}
