package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestIntKeyfactorEnrollmentPatternResource_Import verifies that an enrollment
// pattern can be imported by display name as well as by numeric ID.
// Enrollment patterns require Command v25+; the test skips on older labs.
//
// Step 1 creates the pattern via Terraform (with an associated role, which
//
//	some Command deployments require for pattern creation).
//
// Step 2 imports it by name (the new name-based path) and verifies the
//
//	resulting state matches a subsequent Read.
//
// Step 3 imports it by numeric ID (the pre-existing path) to confirm that
//
//	path is still unbroken after the change.
func TestIntKeyfactorEnrollmentPatternResource_Import(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	// Confirm v25+ by checking that the enrollment patterns API is reachable.
	if _, err := client.GetEnrollmentPatterns(); err != nil {
		t.Skipf("Enrollment patterns API not available (requires Command v25+): %s", err)
	}

	templateID := discoverTemplateID(t, client)
	patternName := acctest.RandomWithPrefix("tf-int-ep-imp")
	roleName := acctest.RandomWithPrefix("tf-int-ep-imp-role")
	resourcePath := "keyfactor_enrollment_pattern.import_test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the enrollment pattern via Terraform (with a role).
			{
				Config: testAccEnrollmentPatternResourceConfig(patternName, roleName, templateID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourcePath, "id"),
					resource.TestCheckResourceAttr(resourcePath, "name", patternName),
					resource.TestCheckResourceAttr(resourcePath, "template_id", fmt.Sprintf("%d", templateID)),
				),
			},
			// Step 2: Import by name — exercises the new name-based import path.
			{
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					return patternName, nil
				},
			},
			// Step 3: Import by numeric ID — confirms the pre-existing path is unbroken.
			{
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				// No ImportStateIdFunc: the test framework uses the resource's
				// "id" attribute from state (the numeric server-assigned ID).
			},
		},
	})
}

// testAccEnrollmentPatternResourceConfig returns a minimal HCL configuration
// for a keyfactor_enrollment_pattern resource. It creates a supporting
// keyfactor_oauth_security_role because some Command deployments require at
// least one associated role when creating an enrollment pattern.
func testAccEnrollmentPatternResourceConfig(patternName, roleName string, templateID int) string {
	return fmt.Sprintf(`
data "keyfactor_permission_set" "ep_import_global" {
  name = "Global"
}

resource "keyfactor_oauth_security_role" "ep_import_test_role" {
  name              = %q
  description       = "Created by terraform-provider integration test"
  permission_set_id = data.keyfactor_permission_set.ep_import_global.id
  permissions       = ["/metadata/types/read/"]
}

resource "keyfactor_enrollment_pattern" "import_test" {
  name                  = %q
  template_id           = %d
  associated_role_names = [keyfactor_oauth_security_role.ep_import_test_role.name]
}
`, roleName, patternName, templateID)
}
