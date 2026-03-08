package keyfactor

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorCertificateTemplateDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate_template")
	var templateName = os.Getenv("KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1")
	if templateName == "" {
		t.Skip("Skipping: KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1 not set")
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "keyfactor_certificate_template" "test" {
  identifier = "%s"
}
`, templateName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "common_name", templateName),
					resource.TestCheckResourceAttrSet(resourceName, "template_name"),
					resource.TestCheckResourceAttrSet(resourceName, "oid"),
					resource.TestCheckResourceAttrSet(resourceName, "key_size"),
					resource.TestCheckResourceAttrSet(resourceName, "key_type"),
					resource.TestCheckResourceAttrSet(resourceName, "forest_root"),
					resource.TestCheckResourceAttrSet(resourceName, "key_retention"),
					resource.TestCheckResourceAttrSet(resourceName, "key_retention_days"),
					resource.TestCheckResourceAttrSet(resourceName, "key_archival"),
					resource.TestCheckResourceAttrSet(resourceName, "allowed_enrollment_types"),
					resource.TestCheckResourceAttrSet(resourceName, "requires_approval"),
					resource.TestCheckResourceAttrSet(resourceName, "key_usage"),
				),
			},
		},
	})
}
