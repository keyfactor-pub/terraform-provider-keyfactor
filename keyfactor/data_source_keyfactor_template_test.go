package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorTemplateDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate_template")
	var shortName = "2YearTestWebServer"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorTemplateBasic(shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "name"),
					resource.TestCheckResourceAttrSet(resourceName, "oid"),
					resource.TestCheckResourceAttrSet(resourceName, "key_size"),
					//resource.TestCheckResourceAttrSet(resourceName, "key_type"), // TODO: Check this
					resource.TestCheckResourceAttrSet(resourceName, "forest_root"),
					//resource.TestCheckResourceAttrSet(resourceName, "friendly_name"), // TODO: Check this
					resource.TestCheckResourceAttrSet(resourceName, "key_retention"),
					resource.TestCheckResourceAttrSet(resourceName, "key_retention_days"),
					resource.TestCheckResourceAttrSet(resourceName, "key_archival"),
					//resource.TestCheckResourceAttrSet(resourceName, "enrollment_fields.#"), // TODO: Check this
					resource.TestCheckResourceAttrSet(resourceName, "allowed_enrollment_types"),
					resource.TestCheckResourceAttrSet(resourceName, "template_regexes.#"),
					resource.TestCheckResourceAttrSet(resourceName, "allowed_requesters.#"),
					resource.TestCheckResourceAttrSet(resourceName, "rfc_enforcement"),
					resource.TestCheckResourceAttrSet(resourceName, "requires_approval"),
					resource.TestCheckResourceAttrSet(resourceName, "key_usage"),
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorTemplateBasic(resourceName string) string {
	return fmt.Sprintf(`
	data "keyfactor_certificate_template" "test" {
		short_name = "%s"
	}
	`, resourceName)
}
