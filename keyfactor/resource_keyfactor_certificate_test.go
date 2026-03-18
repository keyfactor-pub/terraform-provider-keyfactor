package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes — no lab required)
// ---------------------------------------------------------------------------

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
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "certificate_pem"),
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

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "thumbprint"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test_csr", "certificate_pem"),
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
