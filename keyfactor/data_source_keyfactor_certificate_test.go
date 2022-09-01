package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"os"
	"testing"
)

func TestAccKeyfactorCertificateDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate")
	var cID = os.Getenv("KEYFACTOR_CERTIFICATE_ID")
	var password = os.Getenv("KEYFACTOR_CERTIFICATE_PASSWORD")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorCertificateBasic(cID, password),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", cID),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_template"),
					resource.TestCheckResourceAttrSet(resourceName, "dns_sans.#"),
					resource.TestCheckResourceAttrSet(resourceName, "uri_sans.#"),
					resource.TestCheckResourceAttrSet(resourceName, "ip_sans.#"),
					resource.TestCheckResourceAttrSet(resourceName, "metadata.%"),
					resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(resourceName, "subject.%"),
					resource.TestCheckResourceAttrSet(resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(resourceName, "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_chain"),
					resource.TestCheckResourceAttrSet(resourceName, "private_key"),
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorCertificateBasic(resourceName string, password string) string {
	return fmt.Sprintf(`
	data "keyfactor_certificate" "test" {
		id = %s
  		key_password = "%s"
	}
	`, resourceName, password)
}
