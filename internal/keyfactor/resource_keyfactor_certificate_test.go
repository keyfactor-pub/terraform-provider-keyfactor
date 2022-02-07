package keyfactor

import (
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"strconv"
	"testing"
)

func TestAccKeyfactorCertificate_basic(t *testing.T) {
	cN := fmt.Sprintf("tf-acc-test-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	keyPassword := "TerraformAccTestBasic"
	cA := "keyfactor.thedemodrive.com\\\\keyfactor demo drive ca 1"
	template := "DDWebServer1yr"
	deptMeta := "Solutions Engineering"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_certificate.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorCertificate_basic(cN, keyPassword, cA, template),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.certificate_pem"),
				),
			},
			{
				Config: testAccCheckKeyfactorCertificate_modified(cN, keyPassword, cA, template, deptMeta),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.certificate_pem"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.#", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.name", "Department"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.value", deptMeta),
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

		id, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}

		revoked, err := confirmCertificateIsRevoked(id)
		if err != nil {
			return err
		}
		if !revoked {
			return fmt.Errorf("resource still exists, ID: %d", id)
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

func testAccCheckKeyfactorCertificate_basic(commonName string, password string, ca string, template string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
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

func testAccCheckKeyfactorCertificate_modified(commonName string, password string, ca string, template string, deptMeta string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate plus a subject field.
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		certificate {
			subject {
				subject_common_name = "%s"
			}
			key_password = "%s"
			certificate_authority = "%s"
			cert_template = "%s"
			metadata {
				name  = "Department"
				value = "%s"
        	}
		}
	}
	`, commonName, password, ca, template, deptMeta)
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

		conn := testAccProvider.Meta().(*keyfactor.Client)

		id, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}

		request := &keyfactor.GetCertificateContextArgs{Id: id}
		resp, err := conn.GetCertificateContext(request)
		if err != nil {
			return err
		}
		// Check if certificate is active (state 1)
		if resp.CertState != 1 {
			return fmt.Errorf("certificate not active")
		}

		return nil
	}
}
