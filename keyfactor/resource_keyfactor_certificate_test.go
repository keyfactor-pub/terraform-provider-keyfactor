package keyfactor

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAccKeyfactorCertificate_BasicPFX(t *testing.T) {
	skipStore := testAccKeyfactorCertificateCheckSkip()
	if skipStore {
		t.Skip("Skipping certificate acceptance tests (KEYFACTOR_SKIP_CERTIFICATE_TESTS=true)")
	}

	/*
		template, conn, err := getCertificateTemplate(nil)
		if err != nil {
			return
		}
	*/

	template := os.Getenv("KEYFACTOR_CERT_TEMPLATE")

	cA, conn, err := findCompatableCA(nil, 2)
	if err != nil {
		return
	}

	metaField1, _, err := findRandomMetadataField(conn)
	if err != nil {
		return
	}

	metaField2, _, err := findRandomMetadataField(conn)
	if err != nil {
		return
	}

	metaField3, _, err := findRandomMetadataField(conn)
	if err != nil {
		return
	}

	cN := fmt.Sprintf("tf-acc-test-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	keyPassword := "TerraformAccTestBasic"
	meta1 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	meta2 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	meta3 := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_certificate.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorCertificateBasicPFX(cN, keyPassword, cA, template),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
				),
			},
			{
				Config: testAccCheckKeyfactorCertificateModifiedPFX(cN, keyPassword, cA, template, metaField1, meta1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField1), meta1),
				),
			},
			// Test with two metadata fields
			{
				Config: testAccCheckKeyfactorCertificateModifiedPFX2Meta(cN, keyPassword, cA, template, metaField1, meta1, metaField2, meta2),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "2"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField1), meta1),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField2), meta2),
				),
			},
			// Test with three metadata fields
			{
				Config: testAccCheckKeyfactorCertificateModifiedPFX3Meta(cN, keyPassword, cA, template, metaField1, meta1, metaField2, meta2, metaField3, meta3),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "3"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField1), meta1),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField2), meta2),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField3), meta3),
				),
			},
			// Remove the middle metadata field and switch orders
			{
				Config: testAccCheckKeyfactorCertificateModifiedPFX2Meta(cN, keyPassword, cA, template, metaField3, meta3, metaField1, meta1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "2"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField1), meta1),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField3), meta3),
				),
			},
			// Remove all but one metadata field
			{
				Config: testAccCheckKeyfactorCertificateModifiedPFX(cN, keyPassword, cA, template, metaField3, meta3),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField3), meta3),
				),
			},
			// Change single metadata
			{
				Config: testAccCheckKeyfactorCertificateModifiedPFX(cN, keyPassword, cA, template, metaField1, meta1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
					// Check that the change propagated to new state
					//resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField1), meta1),
				),
			},
		},
	})
}

func TestAccKeyfactorCertificate_BasicCsr(t *testing.T) {
	skipStore := testAccKeyfactorCertificateCheckSkip()
	if skipStore {
		t.Skip("Skipping certificate acceptance tests (KEYFACTOR_SKIP_CERTIFICATE_TESTS=true)")
	}

	/*
		template, conn, err := getCertificateTemplate(nil)
		if err != nil {
			return
		}
	*/

	template := os.Getenv("KEYFACTOR_CERT_TEMPLATE")

	cA, conn, err := findCompatableCA(nil, 2)
	if err != nil {
		return
	}

	metaField, _, err := findRandomMetadataField(conn)
	if err != nil {
		return
	}

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
				Config: testAccCheckKeyfactorCertificateBasicCSR(csr, cA, template),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
				),
			},
			{
				Config: testAccCheckKeyfactorCertificateModifiedCSR(cN, cA, template, metaField, meta1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField), meta1),
				),
			},
		},
	})
}

func TestAccKeyfactorCertificate_ExtraPFX(t *testing.T) {
	skipStore := testAccKeyfactorCertificateCheckSkip()
	if skipStore {
		t.Skip("Skipping certificate acceptance tests (KEYFACTOR_SKIP_CERTIFICATE_TESTS=true)")
	}
	template := os.Getenv("KEYFACTOR_CERT_TEMPLATE")

	/*
		template, conn, err := getCertificateTemplate(nil)
		if err != nil {
			return
		}
	*/

	cA, conn, err := findCompatableCA(nil, 2)
	if err != nil {
		return
	}

	metaField, _, err := findRandomMetadataField(conn)
	if err != nil {
		return
	}

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
				Config: testAccCheckKeyfactorCertificateExtraPFX(cn, o, l, c, ou, s, ip4, dns, uri, keyPassword, cA, template, metaField, meta1),
				Check: resource.ComposeTestCheckFunc(
					// todo this should check if DNS was entered properly
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cn),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_organization", o),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_locality", l),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_country", c),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_organizational_unit", ou),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_state", s),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField), meta1),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
				),
			},
			{
				Config: testAccCheckKeyfactorCertificateExtraPFX(cn, o, l, c, ou, s, ip4, dns, uri, keyPassword, cA, template, metaField, meta2),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorCertificateExists("keyfactor_certificate.test"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_common_name", cn),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_organization", o),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_locality", l),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_country", c),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_organizational_unit", ou),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "subject.0.subject_state", s),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_password", keyPassword),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "cert_template", template),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "metadata.%", "1"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("metadata.%s", metaField), meta2),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
				),
			},
		},
	})
}

func testAccKeyfactorCertificateCheckSkip() bool {
	skipCertTests := false
	if temp := os.Getenv("KEYFACTOR_SKIP_CERTIFICATE_TESTS"); temp != "" {
		if strings.ToLower(temp) == "true" {
			skipCertTests = true
		}
	}

	return skipCertTests
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

		request := &keyfactor.GetCertificateContextArgs{Id: id, IncludeMetadata: boolToPointer(true)}
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

func testAccCheckKeyfactorCertificateBasicPFX(commonName string, password string, ca string, template string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		subject {
			subject_common_name = "%s"
		}
		key_password = "%s"
		certificate_authority = "%s"
		cert_template = "%s"
	}
	`, commonName, password, ca, template)
}

func testAccCheckKeyfactorCertificateModifiedPFX(commonName string, password string, ca string, template string, metaName string, metaValue string) string {
	// Return the minimum (basic) required fields to enroll PFX certificate plus a subject field.
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		subject {
			subject_common_name = "%s"
		}
		key_password = "%s"
		certificate_authority = "%s"
		cert_template = "%s"
		metadata = {
			%s   = "%s"
		}
	}
	`, commonName, password, ca, template, metaName, metaValue)
}

func testAccCheckKeyfactorCertificateModifiedPFX2Meta(commonName string, password string, ca string, template string, metaName1 string, metaValue1 string, metaName2 string, metaValue2 string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate plus a subject field.
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		subject {
			subject_common_name = "%s"
		}
		key_password = "%s"
		certificate_authority = "%s"
		cert_template = "%s"
		metadata = {
			%s   = "%s"
			%s   = "%s"
		}
	}
	`, commonName, password, ca, template, metaName1, metaValue1, metaName2, metaValue2)
}

func testAccCheckKeyfactorCertificateModifiedPFX3Meta(commonName string, password string, ca string, template string, metaName1 string, metaValue1 string, metaName2 string, metaValue2 string, metaName3 string, metaValue3 string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate plus a subject field.
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		subject {
			subject_common_name = "%s"
		}
		key_password = "%s"
		certificate_authority = "%s"
		cert_template = "%s"
		metadata = {
			%s   = "%s"
			%s   = "%s"
			%s   = "%s"
		}
	}
	`, commonName, password, ca, template, metaName1, metaValue1, metaName2, metaValue2, metaName3, metaValue3)
}

func testAccCheckKeyfactorCertificateBasicCSR(csr string, ca string, template string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		csr = <<EOT
			  %s
			  EOT
		certificate_authority = "%s"
		cert_template = "%s"
	}
	`, csr, ca, template)
}

func testAccCheckKeyfactorCertificateModifiedCSR(csr string, ca string, template string, metaName string, metaValue string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate plus a subject field.
	return fmt.Sprintf(`
	resource "keyfactor_certificate" "test" {
		csr = <<EOT
			  %s
			  EOT
		certificate_authority = "%s"
		cert_template = "%s"
		metadata = {
			%s  = "%s"
		}
	}
	`, csr, ca, template, metaName, metaValue)
}

func testAccCheckKeyfactorCertificateExtraPFX(cn string, o string, l string, c string, ou string, s string, ip4 string,
	dns string, uri string, password string, ca string, template string, metaName string, metaValue string) string {
	// Return all supported fields to enroll PRX certificate
	return fmt.Sprintf(`resource "keyfactor_certificate" "test" {
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
		metadata = {
			%s  = "%s"
		}
	}
	`, cn, o, l, c, ou, s, ip4, dns, uri, password, ca, template, metaName, metaValue)
}

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
