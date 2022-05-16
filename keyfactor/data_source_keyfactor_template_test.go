package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccKeyfactorDataSourceTemplate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorDataSourceTemplateBasic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "common_name"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "template_name"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "oid"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "key_size"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "key_type"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "forest_root"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "friendly_name"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "key_retention"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "key_retention_days"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "key_archival"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "allowed_enrollment_types"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "use_allowed_requesters"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "use_allowed_requesters"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "allowed_requesters"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "rfc_enforcement"),
					resource.TestCheckResourceAttrSet("keyfactor_template.test", "key_usage"),
				),
			},
		},
	})
}

func testAccKeyfactorDataSourceTemplateBasic() string {
	return fmt.Sprintf(`
	data "keyfactor_template" "test" {}
	`)
}
