package provider

import (
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"strconv"
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
		CheckDestroy:      testAccCheckKeyfactorCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorCertificateBasic(cN, keyPassword, cA, template),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.pfx"),
				),
			},
		},
	})
}

func testAccCheckKeyfactorCertificateDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "keyfactor_certificate" {
			continue
		}
		ID, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}
		exists, err := confirmCertificateIsRevoked(ID)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("resource still exists, ID: %d", ID)
		}
	}
	return nil
}

func confirmCertificateIsRevoked(id int) (bool, error) {
	// retrieve the connection established in Provider configuration
	conn := testAccProvider.Meta().(*keyfactor.Client)

	request := &keyfactor.GetCertificateContextArgs{Id: id}
	resp, err := conn.GetCertificateContext(request)
	if err != nil {
		return false, err
	}
	// Check if certificate is revoked (state 2)
	if resp.CertState != 2 {
		return false, nil
	}

	return true, nil
}

func testAccCheckKeyfactorCertificateBasic(commonName string, password string, ca string, template string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "pfx" {
		certificate {
			subject {
				subject_common_name = "%s"
			}
			key_password = "%s"
			certificate_authority = "%s"
			cert_template = "%s"
		}
	}
	`, commonName, password, ca, template)
}

func testAccCheckKeyfactorCertificateExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]

		if !ok {
			return fmt.Errorf("not found: %s", name)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("no Certificate ID set")
		}

		return nil
	}
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
