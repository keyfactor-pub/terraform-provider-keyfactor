package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorSecurityIdentityDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_identity")
	var iNameEscaped = "COMMAND\\\\Keyfactor-Customer-Admins"
	var iName = "COMMAND\\Keyfactor-Customer-Admins"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccKeyfactorDataSourceSecurityIdentityBasic(iNameEscaped),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "2"),
					resource.TestCheckResourceAttr(resourceName, "account_name", iName),
					resource.TestCheckResourceAttrSet(resourceName, "roles.0"),
					resource.TestCheckResourceAttrSet(resourceName, "identity_type"),
					resource.TestCheckResourceAttrSet(resourceName, "valid"),
				),
			},
		},
	})
}

func testAccKeyfactorDataSourceSecurityIdentityBasic(identityName string) string {
	return fmt.Sprintf(`
	data "keyfactor_identity" "test" {
		account_name = "%s"
	}
	`, identityName)
}
