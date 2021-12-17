package provider

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorCertificateBasic(t *testing.T) {
	cN := "TerraformAccTestBasic"
	keyPassword := "TerraformAccTestBasic"
	cA := "keyfactor.thedemodrive.com\\\\Keyfactor Demo Drive CA 1"
	template := "DDWebServer1yr"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      nil,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorCertificateBasic(cN, keyPassword, cA, template),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(
						"keyfactor_certificate.pfx",
						"certificate[0].certificate_authority",
						regexp.MustCompile(cA),
					),
					resource.TestMatchResourceAttr(
						"keyfactor_certificate.pfx",
						"certificate[0].key_password",
						regexp.MustCompile(keyPassword),
					),
					resource.TestMatchResourceAttr(
						"keyfactor_certificate.pfx",
						"certificate[0].cert_template",
						regexp.MustCompile(template),
					),
					resource.TestMatchResourceAttr(
						"keyfactor_certificate.pfx",
						"certificate[0].subject.subject_common_name",
						regexp.MustCompile(cN),
					),
				),
			},
		},
	})
}

func testAccCheckKeyfactorCertificateBasic(commonName string, password string, ca string, template string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "pfx" {
		certificate {
			subject {
				subject_common_name = %s
			}
			key_password = %s
			certificate_authority = %s
			cert_template = %s
		}
	}
	`, commonName, password, ca, template)
}

func testAccCheckKeyfactorCertificateDestroy(s *terraform.State) error {
	return nil
}

/*
func TestFlattenEnrollResponse(t *testing.T) {
	cases := []struct {
		Input  *keyfactor.EnrollResponse
		Output []interface{}
	}{
		{
			Input: &keyfactor.EnrollResponse{
				Certificates: []string{
					"certificateBinary",
				},
				CertificateInformation: keyfactor.CertificateInformation{
					SerialNumber:       "2D000001F6B013D77F15D3A7BE0000000001F6",
					IssuerDN:           "CN=Keyfactor Demo Drive CA 1, O=Keyfactor Inc",
					Thumbprint:         "087AE0E5473781574AAC84ADD178B759A977DFB2",
					KeyfactorID:        2100,
					KeyfactorRequestID: 1533,
					PKCS12Blob:         "bruh",
					Certificates:       nil,
					RequestDisposition: "ISSUED",
					DispositionMessage: "The private key was successfully retained.",
					EnrollmentContext:  nil,
				},
			},
			Output: []interface{}{
				map[string]interface{}{
					"certificates": []interface{}{
						"certificateBinary",
					},
					"serial_number":        "2D000001F6B013D77F15D3A7BE0000000001F6",
					"issuer_dn":            "CN=Keyfactor Demo Drive CA 1, O=Keyfactor Inc",
					"thumbprint":           "087AE0E5473781574AAC84ADD178B759A977DFB2",
					"keyfactor_id":         2100,
					"keyfactor_request_id": 1533,
				},
			},
		},
	}
	for _, c := range cases {
		out := flattenCertificateItems(c.Input)
		if !reflect.DeepEqual(out, c.Output) {
			t.Fatalf("Error matching output and expected: %#v vs %#v", out, c.Output)
		}
	}
}
*/
