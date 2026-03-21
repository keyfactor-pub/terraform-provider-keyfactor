package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type certificateTestCase struct {
	template     string
	cn           string
	o            string
	l            string
	c            string
	ou           string
	st           string
	email        string
	ipSans       string
	dnsSans      string
	metadata     map[string]string
	keyPassword  string
	ca           string
	resourceName string
	collectionId int
}

// CsrContent is a fixed PEM-encoded CSR with only a CN subject field.
// Using a simple CN-only CSR avoids EJBCA/template subject field restrictions
// (e.g. "Wrong number of LOCALITY fields"). This constant is shared between
// unit tests (VCR cassette recording/replay) and the legacy acceptance tests.
const CsrContent = `-----BEGIN CERTIFICATE REQUEST-----\nMIICaDCCAVACAQAwIzEhMB8GA1UEAxMYdGYtdW5pdC10ZXN0LmV4YW1wbGUuY29t\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApgDKa9ldruZ0AL3rZDkG\nrsXXSihTcU3qB/OUUHoUHG1HMqVGm+jCVBWXm1z+hXmYq2DdesW82ESRQleBwZr5\nDyyKeoypY6ZfqRcmZoHo/sG7e3pYf3fmdn+MnHoNCA7GEipJEV92zYe28WZVCO0U\npe8LTnOt0Dep3F+4no2hO6rRKIYkvlAB58Rp88U/Fnj4xsMrADI0f71+rQPEWMaP\n5oMm+BFCG2m7mvKLciHCqj0oB3OU73ly6Xfw5ezdtDER3CrGSz6SJFBVkzpCqXeP\nfqk1a1o5Vp7kSe6LavaB/bPrPwLFazThZ9JOmaRItX8YVjEdB/oAEpcIFKycxBA3\n/wIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAGJy5PiPu5KCGDtCrmQxNXtlpmEI\n2u0uN/TxYsbpFof8OhqeW0A4JXaS4UZ19A0sIun2GGqTtTHKVbUGLNxWNt7JzOFV\ngA2TrKL1H8J20sXRzNZxZYptfspuAI5Z1BpYpguvGJU+AGA78pw80U5KJN7mFuCf\nX5k143EhCplvclf9FoEgnOXeXSifqTXNvJytNbxLK+RC1urHvg2FpWlRRdcTn+n2\nyxwcTV2W3DruoswVBhnOlvDyoKpjMLSElIhOHg+X3xPtf0RekAmp+wI4LSwf1N3R\ntmwlPVTD69bkiQay2yt0ZX6UZQvcY6QpOEol4MadEhrK6IoXKeZHT+CGzAM=\n-----END CERTIFICATE REQUEST-----\n`

func TestAccKeyfactorCertificateResource(t *testing.T) {

	r := certificateTestCase{
		template:     os.Getenv("KEYFACTOR_CERTIFICATE_TEMPLATE_NAME"),
		cn:           "terraform_test_certificate",
		o:            "Keyfactor Inc.",
		l:            "Independence",
		c:            "US",
		ou:           "Integrations Engineering",
		st:           "OH",
		ca:           fmt.Sprintf(`%s\\%s`, os.Getenv("KEYFACTOR_CERTIFICATE_CA_DOMAIN"), os.Getenv("KEYFACTOR_CERTIFICATE_CA_NAME")),
		ipSans:       `["192.168.0.2", "10.10.0.9"]`,
		dnsSans:      `["tfprovider.keyfactor.com", "terraform_test_certificate"]`,
		metadata:     nil,
		email:        "",
		keyPassword:  os.Getenv("KEYFACTOR_CERTIFICATE_PASSWORD"),
		resourceName: "keyfactor_certificate.PFXCertificate",
	}

	r3 := certificateTestCase{
		template: os.Getenv("KEYFACTOR_CERTIFICATE_TEMPLATE_NAME"),
		cn:       "terraform_test_certificate",
		o:        "",
		l:        "",
		c:        "",
		ou:       "",
		st:       "",
		ca:       fmt.Sprintf(`%s\\%s`, os.Getenv("KEYFACTOR_CERTIFICATE_CA_DOMAIN"), os.Getenv("KEYFACTOR_CERTIFICATE_CA_NAME")),
		//ipSans:       `["192.168.0.2", "10.10.0.9"]`,
		//dnsSans:      `["tfprovider.keyfactor.com", "terraform_test_certificate"]`,
		metadata:     nil,
		email:        "",
		keyPassword:  os.Getenv("KEYFACTOR_CERTIFICATE_PASSWORD"),
		resourceName: "keyfactor_certificate.PFXCertificate",
	}

	r2 := r
	r2.email = "kfadmin@keyfactor.com"

	// Testing PFX certificate
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorCertificateResourcePFXConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(r.resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(r.resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(r.resourceName, "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_chain"),
					resource.TestCheckResourceAttrSet(r.resourceName, "private_key"),

					resource.TestCheckResourceAttrSet(r.resourceName, "subject.%"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_common_name"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_locality"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_organization"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_state"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_country"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_organizational_unit"),
					resource.TestCheckResourceAttrSet(r.resourceName, "key_password"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "ip_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Update and Read testing
			{
				Config: testAccKeyfactorCertificateResourcePFXConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(r.resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(r.resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(r.resourceName, "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_chain"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "ip_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
	// Testing PFX w/ min subject
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorCertificateResourcePFXConfig2(r3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(r.resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(r.resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(r.resourceName, "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_chain"),
					resource.TestCheckResourceAttrSet(r.resourceName, "private_key"),

					resource.TestCheckResourceAttrSet(r.resourceName, "subject.%"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_common_name"),
					//resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_locality"),
					//resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_organization"),
					//resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_state"),
					//resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_country"),
					//resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_organizational_unit"),
					resource.TestCheckResourceAttrSet(r.resourceName, "key_password"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
					//resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
					//resource.TestCheckResourceAttrSet(r.resourceName, "ip_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Update and Read testing
			{
				Config: testAccKeyfactorCertificateResourcePFXConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(r.resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(r.resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(r.resourceName, "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_chain"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "ip_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
	// Testing CSR certificate
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorCertificateResourceCSRConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "csr"),
					//resource.TestCheckResourceAttr(r.resourceName, "csr", CsrContent),
					resource.TestCheckResourceAttrSet(r.resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(r.resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(r.resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(r.resourceName, "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_chain"),
				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Update and Read testing
			{
				Config: testAccKeyfactorCertificateResourcePFXConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
func TestAccKeyfactorCertificateResource_DV_55177(t *testing.T) {
	collectionIdStr := os.Getenv("KEYFACTOR_CERTIFICATE_COLLECTION_ID")
	metadata := make(map[string]string)
	metadata["Email-Contact"] = os.Getenv("KEYFACTOR_CERTIFICATE_EMAIL_CONTACT")
	if metadata["Email-Contact"] == "" {
		metadata["Email-Contact"] = "terraformer@keyfactor.com"
	}
	metadata["Owner"] = os.Getenv("KEYFACTOR_CERTIFICATE_OWNER")
	if metadata["Owner"] == "" {
		metadata["Owner"] = "terraformer"
	}
	collectionId, err := strconv.Atoi(collectionIdStr)
	if err != nil {
		collectionId = 0
	}
	r := certificateTestCase{
		template:     os.Getenv("KEYFACTOR_CERTIFICATE_TEMPLATE_NAME"),
		cn:           "terraform_test_certificate",
		o:            "Keyfactor Inc.",
		l:            "Independence",
		c:            "US",
		ou:           "Integrations Engineering",
		st:           "OH",
		ca:           fmt.Sprintf(`%s\\%s`, os.Getenv("KEYFACTOR_CERTIFICATE_CA_DOMAIN"), os.Getenv("KEYFACTOR_CERTIFICATE_CA_NAME")),
		ipSans:       `["192.168.0.2", "10.10.0.9"]`,
		dnsSans:      `["tfprovider.keyfactor.com", "terraform_test_certificate"]`,
		metadata:     metadata,
		email:        "",
		keyPassword:  os.Getenv("KEYFACTOR_CERTIFICATE_PASSWORD"),
		resourceName: "keyfactor_certificate.PFXCertificate",
		collectionId: collectionId,
	}

	// Use limited user account
	// Save the original value
	adminUsername, adminUsernamePresent := os.LookupEnv("KEYFACTOR_USERNAME")
	terraformUsername, terraformUsernamePresent := os.LookupEnv("TEST_TERRAFORM_USERNAME")

	adminPassword, originalPasswordPresent := os.LookupEnv("KEYFACTOR_PASSWORD")
	terraformPassword, terraformPasswordPresent := os.LookupEnv("TEST_TERRAFORM_PASSWORD")

	if !terraformUsernamePresent || !terraformPasswordPresent {
		t.Fatalf("An account with reduced permissions is needed for this test. `TEST_TERRAFORM_USERNAME` and `TEST_TERRAFORM_PASSWORD` must be set for this test")
		return
	}

	// Set the new value for the test
	err = os.Setenv("KEYFACTOR_USERNAME", terraformUsername)
	if err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	err = os.Setenv("KEYFACTOR_PASSWORD", terraformPassword)
	if err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}

	// Ensure the original value is restored after the test
	defer func() {
		if adminUsernamePresent {
			os.Setenv("KEYFACTOR_USERNAME", adminUsername) // Restore original value
		} else {
			os.Unsetenv("KEYFACTOR_USERNAME") // Ensure the var is removed if it wasn't set before
		}
		if originalPasswordPresent {
			os.Setenv("KEYFACTOR_PASSWORD", adminPassword) // Restore original value
		} else {
			os.Unsetenv("KEYFACTOR_PASSWORD") // Ensure the var is removed if it wasn't set before
		}
	}()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorCertificateResourcePFXConfigCollectionId(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "serial_number"),
					resource.TestCheckResourceAttrSet(r.resourceName, "issuer_dn"),
					resource.TestCheckResourceAttrSet(r.resourceName, "thumbprint"),
					resource.TestCheckResourceAttrSet(r.resourceName, "keyfactor_request_id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_pem"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_chain"),
					resource.TestCheckResourceAttrSet(r.resourceName, "private_key"),

					resource.TestCheckResourceAttrSet(r.resourceName, "subject.%"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_common_name"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_locality"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_organization"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_state"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_country"),
					resource.TestCheckResourceAttrSet(r.resourceName, "subject.subject_organizational_unit"),
					resource.TestCheckResourceAttrSet(r.resourceName, "key_password"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "ip_sans.#"),
					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
					resource.TestCheckResourceAttrSet(r.resourceName, "collection_id"),
					resource.TestCheckResourceAttr(r.resourceName, "collection_id", strconv.Itoa(collectionId)),
				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},

		},
	})

}
func testAccKeyfactorCertificateResourcePFXConfig(t certificateTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_certificate" "PFXCertificate" {
  subject = {
    subject_common_name         = "%s"
    subject_organization        = "%s"
    subject_locality            = "%s"
    subject_country             = "%s"
    subject_organizational_unit = "%s"
    subject_state               = "%s"
  }

  ip_sans  = %s
  dns_sans = %s

  key_password          = "%s" # Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "%s"
  certificate_template  = "%s"
  metadata = {
    "Email-Contact" = "%s" # Note metadata keys must be defined in Keyfactor
  }
}

`, t.cn, t.o, t.l, t.c, t.ou, t.st, t.ipSans, t.dnsSans, t.keyPassword, t.ca, t.template, t.email)
	return output
}
func testAccKeyfactorCertificateResourcePFXConfigCollectionId(t certificateTestCase) string {
	//convert metadata to HCL
	metadataHCL := "{"
	for k, v := range t.metadata {
		metadataHCL += fmt.Sprintf(`"%s" = "%s",`, k, v)
	}
	metadataHCL += "}"
	output := fmt.Sprintf(`
resource "keyfactor_certificate" "PFXCertificate" {
  subject = {
    subject_common_name         = "%s"
    subject_organization        = "%s"
    subject_locality            = "%s"
    subject_country             = "%s"
    subject_organizational_unit = "%s"
    subject_state               = "%s"
  }

  ip_sans  = %s
  dns_sans = %s

  key_password          = "%s" # Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "%s"
  certificate_template  = "%s"
  metadata = %s
  collection_id = %d
}

`, t.cn, t.o, t.l, t.c, t.ou, t.st, t.ipSans, t.dnsSans, t.keyPassword, t.ca, t.template, metadataHCL, t.collectionId)
	return output
}
func testAccKeyfactorCertificateResourcePFXConfig2(t certificateTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_certificate" "PFXCertificate" {
  subject = {
    subject_common_name         = "%s"
    //subject_organization        = "%s"
    //subject_locality            = "%s"
    //subject_country             = "%s"
    //subject_organizational_unit = "%s"
    //subject_state               = "%s"
  }

  //ip_sans  = %s
  //dns_sans = %s

  key_password          = "%s" # Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "%s"
  certificate_template  = "%s"
  metadata = {
    "Email-Contact" = "%s" # Note metadata keys must be defined in Keyfactor
  }
}

`, t.cn, t.o, t.l, t.c, t.ou, t.st, t.ipSans, t.dnsSans, t.keyPassword, t.ca, t.template, t.email)
	return output
}
func testAccKeyfactorCertificateResourceCSRConfig(t certificateTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_certificate" "PFXCertificate" {
  csr = "%s"

  ip_sans  = %s
  dns_sans = %s

  key_password          = "%s" # Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "%s"
  certificate_template  = "%s"
  metadata = {
    "Email-Contact" = "%s" # Note metadata keys must be defined in Keyfactor
  }
}

`, CsrContent, t.ipSans, t.dnsSans, t.keyPassword, t.ca, t.template, t.email)
	return output
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery, only need lab connection env vars)
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateResource_PFX(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-pfx")

	// Try enrollment pattern first (Command v25+), fall back to template+CA
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var config string
	if enrollmentPattern != "" {
		config = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
	} else {
		templateName := discoverTemplate(t, client)
		config = testAccCertPFXConfig(templateName, ca, cn)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "identifier"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_authority"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
				),
			},
		},
	})
}

// checkFormatFields returns a TestCheckFunc that verifies the expected format-specific
// fields are set and all other format fields are empty. Also verifies the resource ID
// has not changed (no recreation).
func checkFormatFields(format string, originalID *string) resource.TestCheckFunc {
	res := "keyfactor_certificate.test"

	// Define which fields each format populates
	pemFields := []string{"certificate_pem", "certificate_chain"}
	binaryFields := map[string]string{
		"PFX": "pfx",
		"JKS": "jks",
		"ZIP": "zip",
	}

	var checks []resource.TestCheckFunc

	// ID stability check
	checks = append(checks, resource.TestCheckResourceAttrWith(res, "id", func(value string) error {
		if *originalID != "" && value != *originalID {
			return fmt.Errorf("certificate was recreated (id changed from %s to %s); expected in-place update", *originalID, value)
		}
		*originalID = value
		return nil
	}))

	effectiveFmt := format
	if effectiveFmt == "" || effectiveFmt == "STORE" {
		effectiveFmt = "PEM"
	}

	switch effectiveFmt {
	case "PEM":
		for _, f := range pemFields {
			checks = append(checks, resource.TestCheckResourceAttrSet(res, f))
		}
		for _, f := range binaryFields {
			checks = append(checks, resource.TestCheckNoResourceAttr(res, f))
		}
	case "PFX":
		checks = append(checks, resource.TestCheckResourceAttrSet(res, "pfx"))
		for _, f := range pemFields {
			checks = append(checks, resource.TestCheckNoResourceAttr(res, f))
		}
		checks = append(checks, resource.TestCheckNoResourceAttr(res, "jks"))
		checks = append(checks, resource.TestCheckNoResourceAttr(res, "zip"))
	case "JKS":
		checks = append(checks, resource.TestCheckResourceAttrSet(res, "jks"))
		for _, f := range pemFields {
			checks = append(checks, resource.TestCheckNoResourceAttr(res, f))
		}
		checks = append(checks, resource.TestCheckNoResourceAttr(res, "pfx"))
		checks = append(checks, resource.TestCheckNoResourceAttr(res, "zip"))
	case "ZIP":
		checks = append(checks, resource.TestCheckResourceAttrSet(res, "zip"))
		for _, f := range pemFields {
			checks = append(checks, resource.TestCheckNoResourceAttr(res, f))
		}
		checks = append(checks, resource.TestCheckNoResourceAttr(res, "pfx"))
		checks = append(checks, resource.TestCheckNoResourceAttr(res, "jks"))
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

// certFormatConfig generates the HCL for a given format using the appropriate
// enrollment method (enrollment pattern or template).
func certFormatConfig(enrollmentPattern, templateName, ca, cn, format string) string {
	if enrollmentPattern != "" {
		return testAccCertPFXConfigEnrollmentPatternWithFormat(enrollmentPattern, ca, cn, format)
	}
	return testAccCertPFXConfigWithFormat(templateName, ca, cn, format)
}

// TestIntKeyfactorCertificateResource_FormatChange verifies that changing
// certificate_format does NOT force resource recreation and that the correct
// format-specific fields are populated for each format. (Fixes #150)
//
// Test flow: default → PEM → PFX → JKS → ZIP → PEM
func TestIntKeyfactorCertificateResource_FormatChange(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-fmt")

	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var templateName string
	if enrollmentPattern == "" {
		templateName = discoverTemplate(t, client)
	}

	var originalID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					checkFormatFields("", &originalID),
				),
			},
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, "PEM"),
				Check:  checkFormatFields("PEM", &originalID),
			},
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, "PFX"),
				Check:  checkFormatFields("PFX", &originalID),
			},
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, "JKS"),
				Check:  checkFormatFields("JKS", &originalID),
			},
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, "ZIP"),
				Check:  checkFormatFields("ZIP", &originalID),
			},
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, "PEM"),
				Check:  checkFormatFields("PEM", &originalID),
			},
		},
	})
}

// TestIntKeyfactorCertificateResource_BothTemplateAndPattern verifies that
// specifying both certificate_template AND certificate_enrollment_pattern
// is accepted by the provider and results in a successful enrollment.
// The API uses the enrollment pattern settings with the template for
// validation. (Fixes #146)
func TestIntKeyfactorCertificateResource_BothTemplateAndPattern(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-both")

	enrollmentPattern := discoverEnrollmentPattern(t, client)
	if enrollmentPattern == "" {
		t.Skip("No enrollment pattern available (pre-v25 lab); skipping both-set test")
	}

	// Get the template that the enrollment pattern is linked to
	templateName := discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
	if templateName == "" {
		t.Skip("Could not determine template for enrollment pattern; skipping both-set test")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertPFXConfigBothTemplateAndPattern(templateName, enrollmentPattern, ca, cn),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate_template", templateName),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate_enrollment_pattern", enrollmentPattern),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateResource_NeitherTemplateNorPattern verifies that
// specifying neither certificate_template nor certificate_enrollment_pattern
// is rejected by the provider with a validation error. (Fixes #146)
func TestIntKeyfactorCertificateResource_NeitherTemplateNorPattern(t *testing.T) {
	_ = testAccIntegrationPreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name            = "tf-int-neither.example.com"
  certificate_authority  = "FakeCA"
  key_password           = "Tftest123456"
}
`),
				ExpectError: regexp.MustCompile(`(?i)at least one of`),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes — no lab required)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateResource_BothTemplateAndPattern verifies that
// specifying both certificate_template AND certificate_enrollment_pattern
// is accepted. VCR version of TestIntKeyfactorCertificateResource_BothTemplateAndPattern.
// (Fixes #146)
func TestUnitKeyfactorCertificateResource_BothTemplateAndPattern(t *testing.T) {
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_resource_both_template_pattern")

	var enrollmentPattern, templateName, ca, cn string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		ca = discoverCA(t, client)
		cn = randomTestCN("tf-unit-both")
		enrollmentPattern = discoverEnrollmentPattern(t, client)
		if enrollmentPattern == "" {
			t.Skip("No enrollment pattern available (pre-v25 lab); skipping both-set test")
		}
		templateName = discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
		if templateName == "" {
			t.Skip("Could not determine template for enrollment pattern; skipping both-set test")
		}
		writeCertPFXTestParams(cassettePath, certPFXTestParams{
			TemplateName:      templateName,
			CA:                ca,
			EnrollmentPattern: enrollmentPattern,
			CN:                cn,
		})
	} else {
		params := readCertPFXTestParams(cassettePath)
		enrollmentPattern = params.EnrollmentPattern
		templateName = params.TemplateName
		ca = params.CA
		cn = params.CN
	}

	factories, cleanup := newVCRProviderFactories(t, "certificate_resource_both_template_pattern")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertPFXConfigBothTemplateAndPattern(templateName, enrollmentPattern, ca, cn),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate_template", templateName),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "certificate_enrollment_pattern", enrollmentPattern),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_NeitherTemplateNorPattern verifies that
// specifying neither certificate_template nor certificate_enrollment_pattern
// is rejected by the provider validation. No cassette needed — validation
// runs before any API calls. (Fixes #146)
func TestUnitKeyfactorCertificateResource_NeitherTemplateNorPattern(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "keyfactor_certificate" "test" {
  common_name            = "tf-unit-neither.example.com"
  certificate_authority  = "FakeCA"
  key_password           = "Tftest123456"
}
`,
				ExpectError: regexp.MustCompile(`(?i)at least one of`),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_FormatChange verifies that changing
// certificate_format does NOT force resource recreation and that the correct
// format-specific fields are populated for each format. (VCR version of
// TestIntKeyfactorCertificateResource_FormatChange — Fixes #150)
//
// Test flow: default → PEM → default
//
// Note: Binary format transitions (PFX/JKS/ZIP) require private key recovery
// from Keyfactor Command, which depends on CA key retention configuration.
// The integration test (TestIntKeyfactorCertificateResource_FormatChange)
// exercises the full format matrix on labs that support recovery.
func TestUnitKeyfactorCertificateResource_FormatChange(t *testing.T) {
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_resource_format_change")

	var enrollmentPattern, templateName, ca, cn string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		ca = discoverCA(t, client)
		cn = randomTestCN("tf-unit-fmt")
		enrollmentPattern = discoverEnrollmentPattern(t, client)
		if enrollmentPattern == "" {
			templateName = discoverTemplate(t, client)
		}
		writeCertPFXTestParams(cassettePath, certPFXTestParams{
			TemplateName:      templateName,
			CA:                ca,
			EnrollmentPattern: enrollmentPattern,
			CN:                cn,
		})
	} else {
		params := readCertPFXTestParams(cassettePath)
		enrollmentPattern = params.EnrollmentPattern
		templateName = params.TemplateName
		ca = params.CA
		cn = params.CN
	}

	factories, cleanup := newVCRProviderFactories(t, "certificate_resource_format_change")
	defer cleanup()

	var originalID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					checkFormatFields("", &originalID),
				),
			},
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, "PEM"),
				Check:  checkFormatFields("PEM", &originalID),
			},
			{
				Config: certFormatConfig(enrollmentPattern, templateName, ca, cn, ""),
				Check:  checkFormatFields("", &originalID),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_PFX tests the full create/read/destroy
// lifecycle of a PFX certificate resource using pre-recorded HTTP cassettes.
//
// To record cassettes against a live lab:
//
//	RECORD_CASSETTES=1 make testunit
func TestUnitKeyfactorCertificateResource_PFX(t *testing.T) {
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_resource_pfx")
	var config string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		ca := discoverCA(t, client)
		cn := randomTestCN("tf-unit-pfx")
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern != "" {
			config = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
		} else {
			templateName = discoverTemplate(t, client)
			config = testAccCertPFXConfig(templateName, ca, cn)
		}
		writeCertPFXTestParams(cassettePath, certPFXTestParams{
			TemplateName:      templateName,
			CA:                ca,
			EnrollmentPattern: enrollmentPattern,
			CN:                cn,
		})
	} else {
		params := readCertPFXTestParams(cassettePath)
		if params.EnrollmentPattern != "" {
			config = testAccCertPFXConfigEnrollmentPattern(params.EnrollmentPattern, params.CA, params.CN)
		} else {
			config = testAccCertPFXConfig(params.TemplateName, params.CA, params.CN)
		}
	}

	factories, cleanup := newVCRProviderFactories(t, "certificate_resource_pfx")
	defer cleanup()

	pfxParams := readCertPFXTestParams(cassettePath)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "identifier"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_chain"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "ca_certificate"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "private_key"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "not_before"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "not_after"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "is_expired", "false"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "is_revoked", "false"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "is_pending_revocation", "false"),
					// Regression: certificate_pem must contain the end-entity cert, not a CA cert.
					// If DownloadCertificate returns certs[0] from a root-first P7B, IsCA=true here.
					testCheckCertPEMIsLeaf("keyfactor_certificate.test", "certificate_pem"),
					testCheckCertPEMCommonName("keyfactor_certificate.test", "certificate_pem", pfxParams.CN),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_CSR tests the full create/read/destroy
// lifecycle of a CSR-based certificate resource using pre-recorded cassettes.
func TestUnitKeyfactorCertificateResource_CSR(t *testing.T) {
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_resource_csr")
	var config string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		ca := discoverCA(t, client)
		cn := randomTestCN("tf-unit-csr")
		csr := generateSimpleCSR(t, cn)
		// CSR enrollment requires a template (enrollment pattern alone is unsupported by the go-client).
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern != "" {
			templateName = discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
		}
		if templateName == "" {
			templateName = discoverTemplate(t, client)
		}
		config = testAccCertCSRConfig(templateName, ca, csr)
		writeCertCSRTestParams(cassettePath, certCSRTestParams{
			TemplateName: templateName,
			CA:           ca,
			CSRPem:       csr,
		})
	} else {
		params := readCertCSRTestParams(cassettePath)
		csr := params.CSRPem
		if csr == "" {
			// Fallback: generate a dummy CSR for replay (body is not matched by VCR)
			csr = generateSimpleCSR(t, "tf-unit-csr-replay.example.com")
		}
		config = testAccCertCSRConfig(params.TemplateName, params.CA, csr)
	}

	factories, cleanup := newVCRProviderFactories(t, "certificate_resource_csr")
	defer cleanup()

	// Derive the expected CN from the stored CSR to assert the downloaded cert is the
	// enrolled end-entity — regression guard for the P7B chain ordering bug.
	csrParams := readCertCSRTestParams(cassettePath)
	enrolledCN := parseCNFromCSRPEM(csrParams.CSRPem)

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "serial_number"),
		resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "thumbprint"),
		resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "certificate_pem"),
		// Regression: certificate_pem must contain the end-entity cert, not a CA cert.
		// If DownloadCertificate returns certs[0] from a root-first P7B, IsCA=true here.
		testCheckCertPEMIsLeaf("keyfactor_certificate.test_csr", "certificate_pem"),
	}
	if enrolledCN != "" {
		checks = append(checks, testCheckCertPEMCommonName("keyfactor_certificate.test_csr", "certificate_pem", enrolledCN))
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.ComposeAggregateTestCheckFunc(checks...),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_CSR_RootFirstChain is a regression test
// for the P7B cert-chain ordering bug. It uses a synthetic cassette where the
// Certificates/Download endpoint returns a root-first P7B (CA cert before
// end-entity).
//
// The bug lives in the Read path (DownloadCertificate returns certs[0] as leaf,
// but certs[0] is the CA when the P7B is root-first). The Create path is
// unaffected — it uses the enrollment response's Certificates[0], which is
// always the correct leaf. To exercise the Read path we use a two-step test:
//   - Step 1: Create (no checks — enrollment state is correct regardless)
//   - Step 2: RefreshState — triggers ReadResource, which calls
//     DownloadCertificate. The testCheckCertPEMIsLeaf check then runs against
//     the refreshed state and FAILS with the bug / PASSES after the fix.
func TestUnitKeyfactorCertificateResource_CSR_RootFirstChain(t *testing.T) {
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("Skipping synthetic cassette test in record mode")
	}

	cassetteName := "certificate_resource_csr_rootfirst"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	// Always regenerate the synthetic cassette — it is built from Go crypto,
	// not recorded from a real lab.
	leafCN := generateRootFirstP7BCassette(t, cassettePath)
	csr := generateSimpleCSR(t, leafCN)

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create only. No checks — the enrollment response always
				// returns the correct leaf cert, so the Create state is clean.
				Config: testAccCertCSRConfig("TestTemplate", "TestCA", csr),
			},
			{
				// Step 2: RefreshState triggers ReadResource → DownloadCertificate.
				// With the bug certs[0] is the CA cert → IsCA=true → testCheckCertPEMIsLeaf FAILS.
				// After fix findLeaf() returns the end-entity → PASS.
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "certificate_pem"),
					testCheckCertPEMIsLeaf("keyfactor_certificate.test_csr", "certificate_pem"),
					testCheckCertPEMCommonName("keyfactor_certificate.test_csr", "certificate_pem", leafCN),
				),
			},
		},
	})
}

func TestIntKeyfactorCertificateResource_CSR(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)

	// CSR enrollment via the go-client requires certificate_template (not enrollment_pattern)
	// because the client library checks that Template is non-empty. When an enrollment pattern
	// is available, discover the template from it; otherwise fall back to discoverTemplate.
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var templateName string
	if enrollmentPattern != "" {
		templateName = discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
	} else {
		templateName = discoverTemplate(t, client)
	}
	// Generate a simple CSR with a unique CN to avoid conflicts on re-runs
	csr := generateSimpleCSR(t, randomTestCN("tf-int-csr"))
	config := testAccCertCSRConfig(templateName, ca, csr)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "issuer_dn"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "certificate_pem"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "certificate_chain"),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateResource_FullSubject verifies that all DN subject
// fields (L, O, ST, C, OU) are accepted and preserved correctly.
func TestIntKeyfactorCertificateResource_FullSubject(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-fullsub")

	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var templateName string
	if enrollmentPattern == "" {
		templateName = discoverTemplate(t, client)
	}

	const (
		locality = "TestCity"
		org      = "TestOrg"
		state    = "TestState"
		country  = "US"
		ou       = "TestOU"
	)
	dnsSANs := genDNSSANs("fullsub.example.com", 2)
	ipSANs := genIPSANs(2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certFullSubjectConfig(enrollmentPattern, templateName, ca, cn, locality, org, state, country, ou, dnsSANs, ipSANs),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "common_name", cn),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "locality", locality),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "organization", org),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "state", state),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "country", country),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "organizational_unit", ou),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.0", dnsSANs[0]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.1", dnsSANs[1]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.0", ipSANs[0]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.1", ipSANs[1]),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateResource_SANs exercises DNS, IP, and URI SANs
// with 0, 1, and 10 entries, plus a mixed-SAN combination.
// Each SAN change forces certificate recreation (RequiresReplace).
func TestIntKeyfactorCertificateResource_SANs(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-sans")

	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var templateName string
	if enrollmentPattern == "" {
		templateName = discoverTemplate(t, client)
	}

	checkDNS := func(n int) resource.TestCheckFunc {
		checks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
			resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.#", fmt.Sprintf("%d", n)),
		}
		for i, s := range genDNSSANs("dns-sans.example.com", n) {
			checks = append(checks, resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("dns_sans.%d", i), s))
		}
		return resource.ComposeAggregateTestCheckFunc(checks...)
	}

	checkIP := func(n int) resource.TestCheckFunc {
		checks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
			resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.#", fmt.Sprintf("%d", n)),
		}
		for i, s := range genIPSANs(n) {
			checks = append(checks, resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("ip_sans.%d", i), s))
		}
		return resource.ComposeAggregateTestCheckFunc(checks...)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// DNS SANs: 0, 1, 10
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, genDNSSANs("dns-sans.example.com", 0), nil, nil),
				Check:  checkDNS(0),
			},
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, genDNSSANs("dns-sans.example.com", 1), nil, nil),
				Check:  checkDNS(1),
			},
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, genDNSSANs("dns-sans.example.com", 10), nil, nil),
				Check:  checkDNS(10),
			},
			// IP SANs: 0, 1, 10
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, nil, genIPSANs(0), nil),
				Check:  checkIP(0),
			},
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, nil, genIPSANs(1), nil),
				Check:  checkIP(1),
			},
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, nil, genIPSANs(10), nil),
				Check:  checkIP(10),
			},
			// URI SANs: 0, 1, 10
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, nil, nil, genURISANs("uri-sans.example.com", 0)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "uri_sans.#", "0"),
				),
			},
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, nil, nil, genURISANs("uri-sans.example.com", 1)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "uri_sans.#"),
				),
			},
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn, nil, nil, genURISANs("uri-sans.example.com", 10)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "uri_sans.#"),
				),
			},
			// Mixed: 3 DNS + 3 IP + 3 URI
			{
				Config: certSANConfig(enrollmentPattern, templateName, ca, cn,
					genDNSSANs("mixed.example.com", 3),
					genIPSANs(3),
					genURISANs("mixed.example.com", 3),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.#", "3"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.#", "3"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "uri_sans.#"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests: Full Subject and SANs (VCR cassettes)
// ---------------------------------------------------------------------------

// loadOrRecordCSRCertParams returns CSR cassette params. In record mode it
// discovers lab resources, generates a CSR, and writes the params file; in
// replay mode it reads the params file and falls back to a dummy CSR.
func loadOrRecordCSRCertParams(t *testing.T, cassettePath string, cnPrefix string) (certCSRTestParams, string) {
	t.Helper()
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		ca := discoverCA(t, client)
		cn := randomTestCN(cnPrefix)
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern != "" {
			templateName = discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
		}
		if templateName == "" {
			templateName = discoverTemplate(t, client)
		}
		csr := generateSimpleCSR(t, cn)
		p := certCSRTestParams{
			TemplateName: templateName,
			CA:           ca,
			CSRPem:       csr,
		}
		writeCertCSRTestParams(cassettePath, p)
		return p, csr
	}
	p := readCertCSRTestParams(cassettePath)
	csr := p.CSRPem
	if csr == "" {
		csr = generateSimpleCSR(t, "tf-unit-csr-meta-replay.example.com")
	}
	return p, csr
}

// loadOrRecordCertParams returns params for a cassette test. In record mode
// it discovers lab resources and writes the params file; in replay mode it reads
// the params file and skips if not found.
func loadOrRecordCertParams(t *testing.T, cassettePath string, cnPrefix string) certPFXTestParams {
	t.Helper()
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		ca := discoverCA(t, client)
		cn := randomTestCN(cnPrefix)
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern == "" {
			templateName = discoverTemplate(t, client)
		}
		p := certPFXTestParams{
			TemplateName:      templateName,
			CA:                ca,
			EnrollmentPattern: enrollmentPattern,
			CN:                cn,
		}
		writeCertPFXTestParams(cassettePath, p)
		return p
	}
	return readCertPFXTestParams(cassettePath)
}

// TestUnitKeyfactorCertificateResource_FullSubject verifies that all six DN
// subject fields (CN, L, O, ST, C, OU) plus DNS and IP SANs are stored and
// can be checked exactly (all are preserved from plan, never from server).
func TestUnitKeyfactorCertificateResource_FullSubject(t *testing.T) {
	cassetteName := "certificate_resource_full_subject"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	p := loadOrRecordCertParams(t, cassettePath, "tf-unit-fullsub")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	const (
		locality = "TestCity"
		org      = "TestOrg"
		state    = "TestState"
		country  = "US"
		ou       = "TestOU"
	)
	dnsSANs := genDNSSANs("fullsub.example.com", 2)
	ipSANs := genIPSANs(2)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certFullSubjectConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, locality, org, state, country, ou, dnsSANs, ipSANs),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "common_name", p.CN),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "locality", locality),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "organization", org),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "state", state),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "country", country),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "organizational_unit", ou),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.0", dnsSANs[0]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.1", dnsSANs[1]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.0", ipSANs[0]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.1", ipSANs[1]),
					testCheckCertPEMIsLeaf("keyfactor_certificate.test", "certificate_pem"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_DNS_SANs exercises DNS SANs with 0, 1,
// and 10 entries. Each change forces certificate recreation (RequiresReplace).
func TestUnitKeyfactorCertificateResource_DNS_SANs(t *testing.T) {
	cassetteName := "certificate_resource_dns_sans"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	p := loadOrRecordCertParams(t, cassettePath, "tf-unit-dns-sans")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	checkDNS := func(n int) resource.TestCheckFunc {
		checks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
			resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.#", fmt.Sprintf("%d", n)),
		}
		for i, s := range genDNSSANs("dns-sans.example.com", n) {
			checks = append(checks, resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("dns_sans.%d", i), s))
		}
		return resource.ComposeAggregateTestCheckFunc(checks...)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, genDNSSANs("dns-sans.example.com", 0), nil, nil),
				Check:  checkDNS(0),
			},
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, genDNSSANs("dns-sans.example.com", 1), nil, nil),
				Check:  checkDNS(1),
			},
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, genDNSSANs("dns-sans.example.com", 10), nil, nil),
				Check:  checkDNS(10),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_IP_SANs exercises IP SANs with 0, 1,
// and 10 entries. Each change forces certificate recreation (RequiresReplace).
func TestUnitKeyfactorCertificateResource_IP_SANs(t *testing.T) {
	cassetteName := "certificate_resource_ip_sans"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	p := loadOrRecordCertParams(t, cassettePath, "tf-unit-ip-sans")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	checkIP := func(n int) resource.TestCheckFunc {
		checks := []resource.TestCheckFunc{
			resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
			resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.#", fmt.Sprintf("%d", n)),
		}
		for i, s := range genIPSANs(n) {
			checks = append(checks, resource.TestCheckResourceAttr("keyfactor_certificate.test", fmt.Sprintf("ip_sans.%d", i), s))
		}
		return resource.ComposeAggregateTestCheckFunc(checks...)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, nil, genIPSANs(0), nil),
				Check:  checkIP(0),
			},
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, nil, genIPSANs(1), nil),
				Check:  checkIP(1),
			},
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, nil, genIPSANs(10), nil),
				Check:  checkIP(10),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_URI_SANs exercises URI SANs with 0, 1,
// and 10 entries. URI SANs are reparsed from the issued certificate on Read
// (unlike DNS/IP which are preserved from plan), so exact values are not
// checked here — only the count for the 0-URI case.
func TestUnitKeyfactorCertificateResource_URI_SANs(t *testing.T) {
	cassetteName := "certificate_resource_uri_sans"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	p := loadOrRecordCertParams(t, cassettePath, "tf-unit-uri-sans")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, nil, nil, genURISANs("uri-sans.example.com", 0)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "uri_sans.#", "0"),
				),
			},
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, nil, nil, genURISANs("uri-sans.example.com", 1)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "uri_sans.#"),
				),
			},
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, nil, nil, genURISANs("uri-sans.example.com", 10)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "uri_sans.#"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateResource_MixedSANs exercises a certificate with
// a mixture of DNS, IP, and URI SANs (3 of each) in a single step.
func TestUnitKeyfactorCertificateResource_MixedSANs(t *testing.T) {
	cassetteName := "certificate_resource_mixed_sans"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	p := loadOrRecordCertParams(t, cassettePath, "tf-unit-mixed-sans")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dnsSANs := genDNSSANs("mixed.example.com", 3)
	ipSANs := genIPSANs(3)
	uriSANs := genURISANs("mixed.example.com", 3)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certSANConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, dnsSANs, ipSANs, uriSANs),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.#", "3"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.0", dnsSANs[0]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.1", dnsSANs[1]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "dns_sans.2", dnsSANs[2]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.#", "3"),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.0", ipSANs[0]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.1", ipSANs[1]),
					resource.TestCheckResourceAttr("keyfactor_certificate.test", "ip_sans.2", ipSANs[2]),
					// URI SANs are reparsed from the cert; check count is non-zero.
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "uri_sans.#"),
					testCheckCertPEMIsLeaf("keyfactor_certificate.test", "certificate_pem"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests: Metadata (PFX and CSR)
// ---------------------------------------------------------------------------

// metaIDStabilityCheck captures the cert ID on first call and verifies it
// does not change on subsequent calls (no unexpected recreation).
func metaIDStabilityCheck(res string, originalID *string) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith(res, "id", func(v string) error {
		if *originalID == "" {
			*originalID = v
		} else if v != *originalID {
			return fmt.Errorf("certificate was unexpectedly recreated (id changed %s → %s)", *originalID, v)
		}
		return nil
	})
}

// TestIntKeyfactorCertificateResource_PFX_Metadata verifies metadata can be
// set on create, updated in-place (no recreation), and removed entirely.
func TestIntKeyfactorCertificateResource_PFX_Metadata(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-pfx-meta")

	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var templateName string
	if enrollmentPattern == "" {
		templateName = discoverTemplate(t, client)
	}

	res := "keyfactor_certificate.test"
	var originalID string

	meta1 := map[string]string{"Owner": "tf-meta-owner", "Email-Contact": "test@example.com"}
	meta2 := map[string]string{"Owner": "tf-meta-owner-updated"}
	meta3 := map[string]string{}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certMetadataConfig(enrollmentPattern, templateName, ca, cn, meta1),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttrSet(res, "serial_number"),
					resource.TestCheckResourceAttr(res, "metadata.%", "2"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-meta-owner"),
					resource.TestCheckResourceAttr(res, "metadata.Email-Contact", "test@example.com"),
				),
			},
			{
				Config: certMetadataConfig(enrollmentPattern, templateName, ca, cn, meta2),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "1"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-meta-owner-updated"),
				),
			},
			{
				Config: certMetadataConfig(enrollmentPattern, templateName, ca, cn, meta3),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "0"),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateResource_CSR_Metadata verifies metadata handling
// for CSR-based certificate enrollment (create, update, remove).
func TestIntKeyfactorCertificateResource_CSR_Metadata(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	cn := randomTestCN("tf-int-csr-meta")

	// CSR enrollment requires a template.
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var templateName string
	if enrollmentPattern != "" {
		templateName = discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
	}
	if templateName == "" {
		templateName = discoverTemplate(t, client)
	}

	csr := generateSimpleCSR(t, cn)

	res := "keyfactor_certificate.test_csr"
	var originalID string

	meta1 := map[string]string{"Owner": "tf-csr-meta-owner", "Email-Contact": "csr-test@example.com"}
	meta2 := map[string]string{"Owner": "tf-csr-meta-owner-updated"}
	meta3 := map[string]string{}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertCSRConfigWithMetadata(templateName, ca, csr, meta1),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttrSet(res, "serial_number"),
					resource.TestCheckResourceAttr(res, "metadata.%", "2"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-csr-meta-owner"),
					resource.TestCheckResourceAttr(res, "metadata.Email-Contact", "csr-test@example.com"),
				),
			},
			{
				Config: testAccCertCSRConfigWithMetadata(templateName, ca, csr, meta2),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "1"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-csr-meta-owner-updated"),
				),
			},
			{
				Config: testAccCertCSRConfigWithMetadata(templateName, ca, csr, meta3),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "0"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests: Metadata (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateResource_PFX_Metadata tests metadata create,
// update, and removal for a PFX/PEM certificate using VCR cassettes.
func TestUnitKeyfactorCertificateResource_PFX_Metadata(t *testing.T) {
	cassetteName := "certificate_resource_pfx_metadata"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	p := loadOrRecordCertParams(t, cassettePath, "tf-unit-pfx-meta")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	res := "keyfactor_certificate.test"
	var originalID string

	meta1 := map[string]string{"Owner": "tf-meta-owner", "Email-Contact": "test@example.com"}
	meta2 := map[string]string{"Owner": "tf-meta-owner-updated"}
	meta3 := map[string]string{}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certMetadataConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, meta1),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttrSet(res, "serial_number"),
					resource.TestCheckResourceAttr(res, "metadata.%", "2"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-meta-owner"),
					resource.TestCheckResourceAttr(res, "metadata.Email-Contact", "test@example.com"),
				),
			},
			{
				Config: certMetadataConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, meta2),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "1"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-meta-owner-updated"),
				),
			},
			{
				Config: certMetadataConfig(p.EnrollmentPattern, p.TemplateName, p.CA, p.CN, meta3),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "0"),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateResource_PFX_KeyTypes verifies PFX enrollment with
// explicit key_type, key_size, and curve values. Each sub-test enrolls a fresh
// certificate and checks that the issued key algorithm is reflected in state.
//
// Supported key types depend on the CA/template configuration in the lab.
// Sub-tests that fail due to unsupported key types will report the CA error.
func TestIntKeyfactorCertificateResource_PFX_KeyTypes(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	templateName := discoverTemplate(t, client)

	type keyTestCase struct {
		name     string
		keyType  string
		keySize  int
		curve    string
		wantType string // expected key_type in state (KeyAlgorithm from server)
	}
	cases := []keyTestCase{
		{name: "RSA-2048", keyType: "RSA", keySize: 2048, curve: "", wantType: "RSA"},
		{name: "RSA-4096", keyType: "RSA", keySize: 4096, curve: "", wantType: "RSA"},
		{name: "ECC-P256", keyType: "ECC", keySize: 0, curve: "P-256", wantType: "ECC"},
		{name: "ECC-P384", keyType: "ECC", keySize: 0, curve: "P-384", wantType: "ECC"},
		{name: "ECC-P521", keyType: "ECC", keySize: 0, curve: "P-521", wantType: "ECC"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cn := randomTestCN("tf-int-key-" + strings.ToLower(tc.name))
			config := testAccCertPFXConfigWithKeyType(templateName, ca, cn, tc.keyType, tc.keySize, tc.curve)
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: config,
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "id"),
							resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
							resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
							resource.TestCheckResourceAttr("keyfactor_certificate.test", "key_type", tc.keyType),
						),
					},
				},
			})
		})
	}
}

// TestIntKeyfactorCertificateResource_CSR_KeyTypes verifies CSR enrollment
// using CSRs generated with different key algorithms (RSA, ECC, Ed25519).
// The key type is embedded in the CSR itself; no key_type field is set in HCL.
func TestIntKeyfactorCertificateResource_CSR_KeyTypes(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	templateName := discoverTemplate(t, client)

	type csrKeyCase struct {
		name    string
		keyType string
		curve   string
	}
	cases := []csrKeyCase{
		{name: "RSA-2048", keyType: "RSA", curve: ""},
		{name: "ECC-P256", keyType: "ECC", curve: "P-256"},
		{name: "ECC-P384", keyType: "ECC", curve: "P-384"},
		{name: "ECC-P521", keyType: "ECC", curve: "P-521"},
		{name: "Ed25519", keyType: "Ed25519", curve: ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cn := randomTestCN("tf-int-csrkey-" + strings.ToLower(tc.name))
			csr := generateCSRWithKeyType(t, cn, tc.keyType, tc.curve)
			config := testAccCertCSRConfig(templateName, ca, csr)
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: config,
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "id"),
							resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "serial_number"),
							resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "thumbprint"),
						),
					},
				},
			})
		})
	}
}

// TestUnitKeyfactorCertificateResource_CSR_Metadata tests metadata create,
// update, and removal for a CSR-based certificate using VCR cassettes.
func TestUnitKeyfactorCertificateResource_CSR_Metadata(t *testing.T) {
	cassetteName := "certificate_resource_csr_metadata"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	p, csr := loadOrRecordCSRCertParams(t, cassettePath, "tf-unit-csr-meta")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	res := "keyfactor_certificate.test_csr"
	var originalID string

	meta1 := map[string]string{"Owner": "tf-csr-meta-owner", "Email-Contact": "csr-test@example.com"}
	meta2 := map[string]string{"Owner": "tf-csr-meta-owner-updated"}
	meta3 := map[string]string{}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertCSRConfigWithMetadata(p.TemplateName, p.CA, csr, meta1),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttrSet(res, "serial_number"),
					resource.TestCheckResourceAttr(res, "metadata.%", "2"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-csr-meta-owner"),
					resource.TestCheckResourceAttr(res, "metadata.Email-Contact", "csr-test@example.com"),
				),
			},
			{
				Config: testAccCertCSRConfigWithMetadata(p.TemplateName, p.CA, csr, meta2),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "1"),
					resource.TestCheckResourceAttr(res, "metadata.Owner", "tf-csr-meta-owner-updated"),
				),
			},
			{
				Config: testAccCertCSRConfigWithMetadata(p.TemplateName, p.CA, csr, meta3),
				Check: resource.ComposeAggregateTestCheckFunc(
					metaIDStabilityCheck(res, &originalID),
					resource.TestCheckResourceAttr(res, "metadata.%", "0"),
				),
			},
		},
	})
}
