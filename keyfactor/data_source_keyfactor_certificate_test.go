package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes — no lab required)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateDataSource tests the certificate data source
// read path using pre-recorded HTTP cassettes.
//
// To record cassettes against a live lab:
//
//	KEYFACTOR_CERTIFICATE_ID=<id> RECORD_CASSETTES=1 make testunit
func TestUnitKeyfactorCertificateDataSource(t *testing.T) {
	// The data source reads an existing cert. In recording mode, first create one
	// to get a stable ID, then read it back — just like TestIntKeyfactorCertificateDataSource.
	// In replay mode, use the cert resource + data source combo config so the cassette
	// interactions match (certificate ID is resolved via the resource reference).
	resourceName := "data.keyfactor_certificate.test"
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_data_source")

	var config string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		ca := discoverCA(t, client)
		cn := randomTestCN("tf-unit-ds")
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var certConfig string
		var templateName string
		if enrollmentPattern != "" {
			certConfig = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
		} else {
			templateName = discoverTemplate(t, client)
			certConfig = testAccCertPFXConfig(templateName, ca, cn)
		}
		writeCertPFXTestParams(cassettePath, certPFXTestParams{
			TemplateName:      templateName,
			CA:                ca,
			EnrollmentPattern: enrollmentPattern,
			CN:                cn,
		})
		config = certConfig + "\n" + testAccCertDataSourceByID("keyfactor_certificate.test")
	} else {
		params := readCertPFXTestParams(cassettePath)
		var certConfig string
		if params.EnrollmentPattern != "" {
			certConfig = testAccCertPFXConfigEnrollmentPattern(params.EnrollmentPattern, params.CA, params.CN)
		} else {
			certConfig = testAccCertPFXConfig(params.TemplateName, params.CA, params.CN)
		}
		config = certConfig + "\n" + testAccCertDataSourceByID("keyfactor_certificate.test")
	}

	factories, cleanup := newVCRProviderFactories(t, "certificate_data_source")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					// Data source field coverage
					resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_chain"),
					resource.TestCheckResourceAttrSet(resourceName, "ca_certificate"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate_id"),
					resource.TestCheckResourceAttrSet(resourceName, "not_before"),
					resource.TestCheckResourceAttrSet(resourceName, "not_after"),
					resource.TestCheckResourceAttr(resourceName, "is_expired", "false"),
					resource.TestCheckResourceAttr(resourceName, "is_revoked", "false"),
					resource.TestCheckResourceAttr(resourceName, "is_pending_revocation", "false"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-ds")

	// Try enrollment pattern first (Command v25+), fall back to template+CA
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var certConfig string
	if enrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
	} else {
		templateName := discoverTemplate(t, client)
		certConfig = testAccCertPFXConfig(templateName, ca, cn)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// First create a certificate, then read it back via data source
				Config: certConfig + "\n" +
					testAccCertDataSourceByID("keyfactor_certificate.test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Resource checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					// Data source field coverage
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "ca_certificate"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "not_before"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate.test", "not_after"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate.test", "is_expired", "false"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate.test", "is_revoked", "false"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate.test", "is_pending_revocation", "false"),
				),
			},
		},
	})
}
