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

// TestIntKeyfactorCertificateCollectionResource_Import verifies that a
// certificate collection can be imported by display name as well as by
// numeric ID.
//
// Step 1 creates the collection via Terraform.
// Step 2 imports it by name (the new name-based path) and verifies the
//
//	resulting state matches a subsequent Read.
//
// Step 3 imports it by numeric ID (the pre-existing path) to confirm that
//
//	path is still unbroken after the change.
//
// Note: the `query` field is excluded from ImportStateVerify because the
// GetById endpoint never returns the query expression — Read() preserves it
// from prior state, so an import always produces a null query in the
// imported state while the prior state holds the declared value.
func TestIntKeyfactorCertificateCollectionResource_Import(t *testing.T) {
	testAccIntegrationPreCheck(t)

	name := acctest.RandomWithPrefix("tf-int-col-imp")
	query := fmt.Sprintf(`CN -contains "%s"`, name)
	resourcePath := "keyfactor_certificate_collection.import_test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the collection via Terraform.
			{
				Config: testAccCertificateCollectionResourceConfig(name, query),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourcePath, "id"),
					resource.TestCheckResourceAttr(resourcePath, "name", name),
					resource.TestCheckResourceAttr(resourcePath, "query", query),
				),
			},
			// Step 2: Import by name — exercises the new name-based import path.
			{
				ResourceName:            resourcePath,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"query"},
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					return name, nil
				},
			},
			// Step 3: Import by numeric ID — confirms the pre-existing path is unbroken.
			{
				ResourceName:            resourcePath,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"query"},
				// No ImportStateIdFunc: the test framework uses the resource's
				// "id" attribute from state (the numeric server-assigned ID).
			},
		},
	})
}

// testAccCertificateCollectionResourceConfig returns a minimal HCL
// configuration for a keyfactor_certificate_collection resource with the
// given name and query expression.
func testAccCertificateCollectionResourceConfig(name, query string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_collection" "import_test" {
  name  = %q
  query = %q
}
`, name, query)
}
