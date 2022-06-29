package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccKeyfactorDataSourceSecurityRole(t *testing.T) {
	t.Skip()
	roleName := "Administrator"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorDataSourceSecurityRoleBasic(roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("keyfactor_security_role.test", "role_name", roleName),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "description"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "identities"),
					resource.TestCheckResourceAttrSet("keyfactor_security_role.test", "permissions"),
				),
			},
		},
	})
}

func testAccKeyfactorDataSourceSecurityRoleBasic(roleName string) string {
	return fmt.Sprintf(`
	data "keyfactor_security_role" "test" {
		role_name = "%s"
	}
	`, roleName)
}
