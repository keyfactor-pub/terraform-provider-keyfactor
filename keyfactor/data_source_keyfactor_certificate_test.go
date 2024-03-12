package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"os"
	"testing"
)

func TestAccKeyfactorCertificateDataSource(t *testing.T) {
	var resourceType = "keyfactor_certificate"
	var resourceName = fmt.Sprintf("data.%s.test", resourceType)
	var cID = os.Getenv("KEYFACTOR_CERTIFICATE_ID")
	if cID == "" {
		cID = os.Getenv("TEST_CERTIFICATE_ID")
		if cID == "" {
			cID = os.Getenv("TEST_CERTIFICATE_CN")
			if cID == "" {
				cID = "1"
			}
		}
	}
	var password = os.Getenv("KEYFACTOR_CERTIFICATE_PASSWORD")
	if password == "" {
		password = os.Getenv("TEST_CERTIFICATE_PASSWORD")
		if password == "" {
			password = "Password1234!"
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorCertificateBasic(resourceType, cID, password),
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
					//resource.TestCheckResourceAttrSet(resourceName, "private_key"),
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorCertificateBasic(resourceName string, id string, password string) string {
	output := fmt.Sprintf(`
	data "%s" "test" {
		identifier = "%s"
  		key_password = "%s"
	}
	`, resourceName, id, password)
	return output
}
