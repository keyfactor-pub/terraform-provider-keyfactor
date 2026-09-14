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
// Step 1 creates the pattern via Terraform.
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
	name := acctest.RandomWithPrefix("tf-int-ep-imp")
	resourcePath := "keyfactor_enrollment_pattern.import_test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the enrollment pattern via Terraform.
			{
				Config: testAccEnrollmentPatternResourceConfig(name, templateID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourcePath, "id"),
					resource.TestCheckResourceAttr(resourcePath, "name", name),
					resource.TestCheckResourceAttr(resourcePath, "template_id", fmt.Sprintf("%d", templateID)),
				),
			},
			// Step 2: Import by name — exercises the new name-based import path.
			{
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					return name, nil
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
// for a keyfactor_enrollment_pattern resource with the given name and
// template_id. All other attributes are Optional+Computed and can be
// omitted; the server fills them in with defaults.
func testAccEnrollmentPatternResourceConfig(name string, templateID int) string {
	return fmt.Sprintf(`
resource "keyfactor_enrollment_pattern" "import_test" {
  name        = %q
  template_id = %d
}
`, name, templateID)
}
