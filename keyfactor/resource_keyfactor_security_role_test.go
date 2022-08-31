package keyfactor

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
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
		name:        "TerraformTest",
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
