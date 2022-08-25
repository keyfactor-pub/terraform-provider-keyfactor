package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorCertificateStoreDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate_store")
	var sID = "9f8855f1-80ff-4475-89ec-d82accb32cea"
	var sPass = "changeme!"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorCertificateStoreBasic(sID, sPass),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", sID),
					resource.TestCheckResourceAttr(resourceName, "password", sPass),
					resource.TestCheckResourceAttrSet(resourceName, "store_path"),
					resource.TestCheckResourceAttrSet(resourceName, "store_type"),
					resource.TestCheckResourceAttrSet(resourceName, "approved"),
					resource.TestCheckResourceAttrSet(resourceName, "create_if_missing"),
					//resource.TestCheckResourceAttrSet(resourceName, "properties"), //TODO: Check this
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttrSet(resourceName, "agent_assigned"),
					//resource.TestCheckResourceAttrSet(resourceName, "container_name"), //TODO: Check this
					//resource.TestCheckResourceAttrSet(resourceName, "inventory_schedule"), //TODO: Check this
					resource.TestCheckResourceAttrSet(resourceName, "set_new_password_allowed"),
					//resource.TestCheckResourceAttrSet(resourceName, "certificates.#"), //TODO: Check this
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorCertificateStoreBasic(resourceName string, password string) string {
	return fmt.Sprintf(`
	data "keyfactor_certificate_store" "test" {
		id = "%s"
		password = "%s"
	}
	`, resourceName, password)
}
