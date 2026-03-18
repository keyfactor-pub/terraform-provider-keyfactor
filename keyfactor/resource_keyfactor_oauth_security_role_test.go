package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

type oauthRoleTestCase struct {
	name         string
	description  string
	permissions  []string
	emailAddress string
	resourceType string
	resourceName string
	resourcePath string
}

func TestAccKeyfactorOAuthRoleResource(t *testing.T) {

	r := oauthRoleTestCase{
		name:         acctest.RandomWithPrefix("tf-acc-role"),
		description:  "Terraform Create Role",
		permissions:  []string{"/metadata/types/read/"},
		emailAddress: "foo@example.com",
		resourceType: "keyfactor_oauth_security_role",
		resourceName: "terraform_test",
		resourcePath: "keyfactor_oauth_security_role.terraform_test",
	}

	// Update role attributes
	r2 := r
	r2.description = "Terraform Update Claim"
	r2.permissions = []string{"/certificates/"}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create role
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "permission_set_id"),
					resource.TestCheckResourceAttr(r.resourcePath, "permissions.0", r.permissions[0]),
					resource.TestCheckResourceAttr(r.resourcePath, "name", r.name),
					resource.TestCheckResourceAttr(r.resourcePath, "description", r.description),
					resource.TestCheckResourceAttr(r.resourcePath, "email_address", r.emailAddress),
				),
			},
			// Update role
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttr(r2.resourcePath, "permissions.0", r2.permissions[0]),
					resource.TestCheckResourceAttr(r2.resourcePath, "description", r2.description),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccKeyfactorOAuthRoleResourceDuplicateUnsortedPermissions(t *testing.T) {

	r := oauthRoleTestCase{
		name:         acctest.RandomWithPrefix("tf-acc-role"),
		description:  "Terraform Create Role",
		permissions:  []string{"/metadata/types/read/", "/certificates/", "/metadata/types/read/"},
		emailAddress: "foo@example.com",
		resourceType: "keyfactor_oauth_security_role",
		resourceName: "terraform_test",
		resourcePath: "keyfactor_oauth_security_role.terraform_test",
	}

	// Update role attributes
	r2 := r
	r2.permissions = []string{"/metadata/types/read/", "/metadata/types/read/", "/dashboard/read/"}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create role
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "permission_set_id"),
					resource.TestCheckResourceAttr(r.resourcePath, "name", r.name),
					resource.TestCheckResourceAttr(r.resourcePath, "description", r.description),
					resource.TestCheckResourceAttr(r.resourcePath, "email_address", r.emailAddress),
				),
			}, // Update role
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccKeyfactorOAuthRoleImportState(t *testing.T) {
	r := oauthRoleTestCase{
		name:         acctest.RandomWithPrefix("tf-acc-role"),
		description:  "Terraform Import Role",
		permissions:  []string{"/metadata/types/read/"},
		emailAddress: "foo@example.com",
		resourceType: "keyfactor_oauth_security_role",
		resourceName: "terraform_test",
		resourcePath: "keyfactor_oauth_security_role.terraform_test",
	}

	resourcePath := fmt.Sprintf("%s.%s", r.resourceType, r.resourceName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create role
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r),
			}, // Import State
			{
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					// Use the known roleName to construct the import ID
					return r.name, nil
				},
			},
		},
	})
}

func testAccKeyfactorOAuthRoleResourceConfig(t oauthRoleTestCase) string {
	var permissionString string
	for _, permission := range t.permissions {
		if permissionString != "" {
			permissionString += ","
		}
		permissionString += fmt.Sprintf("\"%s\"", permission)
	}
	output := fmt.Sprintf(`	
data "keyfactor_permission_set" "global_permission_set" {
     name = "Global"
}

resource "%s" "%s" {
	name = "%s"
	description  = "%s"
	permission_set_id  = data.keyfactor_permission_set.global_permission_set.id
	email_address = "%s"
	permissions = [%s]
}
`, t.resourceType, t.resourceName, t.name, t.description, t.emailAddress, permissionString)
	return output
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorOAuthRoleResource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	r := oauthRoleTestCase{
		name:         acctest.RandomWithPrefix("tf-int-role"),
		description:  "Integration test role",
		permissions:  []string{"/metadata/types/read/"},
		emailAddress: "int-test@example.com",
		resourceType: "keyfactor_oauth_security_role",
		resourceName: "int_test",
		resourcePath: "keyfactor_oauth_security_role.int_test",
	}

	r2 := r
	r2.description = "Integration test role updated"
	r2.permissions = []string{"/certificates/"}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "permission_set_id"),
					resource.TestCheckResourceAttr(r.resourcePath, "name", r.name),
					resource.TestCheckResourceAttr(r.resourcePath, "description", r.description),
					resource.TestCheckResourceAttr(r.resourcePath, "email_address", r.emailAddress),
					resource.TestCheckResourceAttr(r.resourcePath, "permissions.0", r.permissions[0]),
				),
			},
			// Update description and permissions
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourcePath, "id"),
					resource.TestCheckResourceAttr(r2.resourcePath, "description", r2.description),
					resource.TestCheckResourceAttr(r2.resourcePath, "permissions.0", r2.permissions[0]),
				),
			},
		},
	})
}

func TestIntKeyfactorOAuthRoleResource_Import(t *testing.T) {
	testAccIntegrationPreCheck(t)

	r := oauthRoleTestCase{
		name:         acctest.RandomWithPrefix("tf-int-role-imp"),
		description:  "Integration test role import",
		permissions:  []string{"/metadata/types/read/"},
		emailAddress: "int-import@example.com",
		resourceType: "keyfactor_oauth_security_role",
		resourceName: "int_import_test",
		resourcePath: "keyfactor_oauth_security_role.int_import_test",
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r),
			},
			{
				ResourceName:      r.resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					return r.name, nil
				},
			},
		},
	})
}
