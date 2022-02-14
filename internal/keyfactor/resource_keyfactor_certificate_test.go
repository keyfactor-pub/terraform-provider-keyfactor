package keyfactor

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strconv"
	"testing"
)

func TestAccKeyfactorCertificate_BasicPFX(t *testing.T) {
	template, cA, metaField := testAccKeyfactorCertificateGetConfig(t)

	cN := fmt.Sprintf("tf-acc-test-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	keyPassword := "TerraformAccTestBasic"
	meta1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_certificate.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorCertificate_BasicPFX(cN, keyPassword, cA, template),
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
				Config: testAccCheckKeyfactorCertificate_ModifiedPFX(cN, keyPassword, cA, template, metaField, meta1),
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
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.name", metaField),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.value", meta1),
				),
			},
		},
	})
}

func TestAccKeyfactorCertificate_BasicCsr(t *testing.T) {
	template, cA, metaField := testAccKeyfactorCertificateGetConfig(t)

	cN := fmt.Sprintf("tf-acc-test-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	meta1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	csr := generateCSR(cN)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_certificate.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorCertificate_BasicCSR(csr, cA, template),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
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
				Config: testAccCheckKeyfactorCertificate_ModifiedCSR(cN, cA, template, metaField, meta1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
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
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.name", metaField),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.value", meta1),
				),
			},
		},
	})
}

func TestAccKeyfactorCertificate_ExtraPFX(t *testing.T) {
	template, cA, metaField := testAccKeyfactorCertificateGetConfig(t)
	cn := fmt.Sprintf("tf-acc-test-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	o := "coolcompany"
	l := "Springfield"
	c := "US"
	ou := "it"
	s := "mo"
	ip4 := "192.168.226.123"
	dns := "cool.example.com"
	uri := "example.com"
	// cn string, o string, l string, c string, ou string, s string, ip4 string,
	//	dns string, uri string, password string, ca string, template string, deptMeta string
	keyPassword := "TerraformAccTestExtra"

	// Generate arbitrary data, we don't actually care what this data is as long as the transmission works
	meta1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	meta2 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_certificate.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorCertificate_ExtraPFX(cn, o, l, c, ou, s, ip4, dns, uri, keyPassword, cA, template, metaField, meta1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_common_name", cn),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_organization", o),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_locality", l),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_country", c),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_organizational_unit", ou),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_state", s),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.cert_template", template),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.#", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.name", metaField),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.value", meta1),
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
				Config: testAccCheckKeyfactorCertificate_ExtraPFX(cn, o, l, c, ou, s, ip4, dns, uri, keyPassword, cA, template, metaField, meta2),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_common_name", cn),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_organization", o),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_locality", l),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_country", c),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_organizational_unit", ou),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.subject.0.subject_state", s),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.cert_template", template),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.#", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.name", metaField),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate.0.metadata.0.value", meta2),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate.0.certificate_pem"),
				),
			},
		},
	})
}

func testAccKeyfactorCertificateGetConfig(t *testing.T) (string, string, string) {
	var template, ca, metaField1 string
	if template = os.Getenv("KEYFACTOR_CERT_TEMPLATE"); template == "" {
		t.Log("Note: Terraform Certificate Acceptance tests attempt to enroll certificates based on a certificate " +
			"template. Ensure that this is supported by Keyfactor Command")
		t.Fatal("KEYFACTOR_CERT_TEMPLATE must be set to perform certificate acceptance test. (EX 'WebServer1y')")
	}
	if ca = os.Getenv("KEYFACTOR_CERTIFICATE_AUTHORITY"); ca == "" {
		t.Fatal("KEYFACTOR_CERTIFICATE_AUTHORITY must be set to perform certificate acceptance test" +
			" (EX '<host>\\\\<logical>')")
	}
	if metaField1 = os.Getenv("KEYFACTOR_TEST_METADATA_FIELD"); metaField1 == "" {
		t.Log("Note: Terraform Certificate Acceptance tests create and update certificate metadata. Metadata " +
			"fields depend on the specific Keyfactor instance, populate this variable with the name of one Metadata " +
			"field")
		t.Fatal("KEYFACTOR_TEST_METADATA_FIELD must be set to perform certificate acceptance test. (EX 'ContainerName')")
	}

	return template, ca, metaField1
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

func testAccCheckKeyfactorCertificate_BasicPFX(commonName string, password string, ca string, template string) string {
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

func testAccCheckKeyfactorCertificate_ModifiedPFX(commonName string, password string, ca string, template string, metaName string, metaValue string) string {
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
				name  = "%s"
				value = "%s"
        	}
		}
	}
	`, commonName, password, ca, template, metaName, metaValue)
}

func testAccCheckKeyfactorCertificate_BasicCSR(csr string, ca string, template string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		certificate {
			csr = <<EOT
                  %s
			      EOT
			certificate_authority = "%s"
			cert_template = "%s"
		}
	}
	`, csr, ca, template)
}

func testAccCheckKeyfactorCertificate_ModifiedCSR(csr string, ca string, template string, metaName string, metaValue string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate plus a subject field.
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		certificate {
			csr = <<EOT
                  %s
			      EOT
			certificate_authority = "%s"
			cert_template = "%s"
			metadata {
				name  = "%s"
				value = "%s"
        	}
		}
	}
	`, csr, ca, template, metaName, metaValue)
}

func testAccCheckKeyfactorCertificate_ExtraPFX(cn string, o string, l string, c string, ou string, s string, ip4 string,
	dns string, uri string, password string, ca string, template string, metaName string, metaValue string) string {
	// Return all supported fields to enroll PRX certificate
	return fmt.Sprintf(`resource "keyfactor_certificate" "test" {
		certificate {
			subject {
				subject_common_name         = "%s"
				subject_organization        = "%s"
            	subject_locality            = "%s"
            	subject_country             = "%s"
				subject_organizational_unit = "%s"
 			    subject_state               = "%s"
			}
			sans {
				san_ip4 = ["%s"]
				san_dns = ["%s"]
				san_uri = ["%s"]
			}
			key_password = "%s"
			certificate_authority = "%s"
			cert_template = "%s"
			metadata {
				name  = "%s"
				value = "%s"
        	}
		}
	}
	`, cn, o, l, c, ou, s, ip4, dns, uri, password, ca, template, metaName, metaValue)
}

// todo deploy test

func generateCSR(commonName string) string {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj := pkix.Name{
		CommonName: commonName,
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err := pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return ""
	}

	return csrBuf.String()
}
