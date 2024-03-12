package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"os"
	"testing"
)

func TestAccKeyfactorCertificateStoreDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate_store")
	var sID = os.Getenv("TEST_CERTIFICATE_STORE_ID")
	if sID == "" {
		sID = os.Getenv("KEYFACTOR_CERTIFICATE_STORE_ID")
		if sID == "" {
			sID = "1"
		}
	}
	var sPass = os.Getenv("KEYFACTOR_CERTIFICATE_STORE_PASS")
	if sPass == "" {
		sPass = os.Getenv("TEST_CERTIFICATE_STORE_PASS")
		if sPass == "" {
			sPass = "password1234!"
		}
	}

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
					resource.TestCheckResourceAttrSet(resourceName, "properties.%"),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttrSet(resourceName, "agent_assigned"),
					resource.TestCheckResourceAttrSet(resourceName, "container_name"),
					//resource.TestCheckResourceAttrSet(resourceName, "inventory_schedule"), //TODO: Check this when implemented
					resource.TestCheckResourceAttrSet(resourceName, "set_new_password_allowed"),
					//resource.TestCheckResourceAttrSet(resourceName, "certificates.#"), //TODO: Check this when implemented
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
