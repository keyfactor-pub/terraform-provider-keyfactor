package keyfactor

//import (
//	"fmt"
//	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
//	"os"
//	"testing"
//)
//
//type certificateDeploymentTestCase struct {
//	certificateTestCase
//	storeID string
//}
//
//func TestAccKeyfactorCertificateDeploymentResource(t *testing.T) {
//
//	r := certificateDeploymentTestCase{
//		certificateTestCase: certificateTestCase{
//			template:     os.Getenv("KEYFACTOR_CERTIFICATE_TEMPLATE_NAME"),
//			cn:           "terraform_test_certificate",
//			o:            "Keyfactor Inc.",
//			l:            "Independence",
//			c:            "US",
//			ou:           "Integrations Engineering",
//			st:           "OH",
//			ca:           fmt.Sprintf(`%s\\%s`, os.Getenv("KEYFACTOR_CERTIFICATE_CA_DOMAIN"), os.Getenv("KEYFACTOR_CERTIFICATE_CA_NAME")),
//			ipSans:       `["192.168.0.2", "10.10.0.9"]`,
//			dnsSans:      `["tfprovider.keyfactor.com", "terraform_test_certificate"]`,
//			metadata:     nil,
//			email:        "",
//			keyPassword:  os.Getenv("KEYFACTOR_CERTIFICATE_PASSWORD"),
//			resourceName: "keyfactor_certificate_deployment.PFXCertificate",
//		},
//		storeID: os.Getenv("KEYFACTOR_CERTIFICATE_STORE_ID"),
//	}
//
//	// Testing PFX certificate
//	resource.Test(t, resource.TestCase{
//		PreCheck:                 func() { testAccPreCheck(t) },
//		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
//		Steps: []resource.TestStep{
//			// Create and Read testing
//			{
//				//ResourceName: "",
//				//PreConfig:    nil,
//				//Taint:        nil,
//				Config: testAccKeyfactorCertificateDeploymentResourcePFXConfig(r),
//				Check: resource.ComposeAggregateTestCheckFunc(
//					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
//				),
//				//Destroy:                   false,
//				//ExpectNonEmptyPlan:        false,
//				//ExpectError:               nil,
//				//PlanOnly:                  false,
//				//PreventDiskCleanup:        false,
//				//PreventPostDestroyRefresh: false,
//				//SkipFunc:                  nil,
//				//ImportState:               false,
//				//ImportStateId:             "",
//				//ImportStateIdPrefix:       "",
//				//ImportStateIdFunc:         nil,
//				//ImportStateCheck:          nil,
//				//ImportStateVerify:         false,
//				//ImportStateVerifyIgnore:   nil,
//				//ProviderFactories:         nil,
//				//ProtoV5ProviderFactories:  nil,
//				//ProtoV6ProviderFactories:  nil,
//				//ExternalProviders:         nil,
//			},
//			// ImportState testing
//			//{
//			//	ResourceName:      "scaffolding_example.test",
//			//	ImportState:       false,
//			//	ImportStateVerify: false,
//			//	// This is not normally necessary, but is here because this
//			//	// example code does not have an actual upstream service.
//			//	// Once the Read method is able to refresh information from
//			//	// the upstream service, this can be removed.
//			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
//			//},
//			// Update and Read testing
//			{
//				Config: testAccKeyfactorCertificateDeploymentResourcePFXConfig(r),
//				Check: resource.ComposeAggregateTestCheckFunc(
//					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "serial_number"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "issuer_dn"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "thumbprint"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "keyfactor_request_id"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_pem"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_chain"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_authority"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "certificate_template"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "dns_sans.#"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "ip_sans.#"),
//					resource.TestCheckResourceAttrSet(r.resourceName, "metadata.%"),
//				),
//			},
//			// Delete testing automatically occurs in TestCase
//		},
//	})
//}
//
//func testAccKeyfactorCertificateDeploymentResourcePFXConfig(t certificateDeploymentTestCase) string {
//	output := fmt.Sprintf(`
//resource "keyfactor_certificate" "PFXCertificate" {
//  subject = {
//    subject_common_name         = "%s"
//    subject_organization        = "%s"
//    subject_locality            = "%s"
//    subject_country             = "%s"
//    subject_organizational_unit = "%s"
//    subject_state               = "%s"
//  }
//
//  ip_sans  = %s
//  dns_sans = %s
//
//  key_password          = "%s" # Please don't use this password in production pass in an environmental variable or something
//  certificate_authority = "%s"
//  certificate_template  = "%s"
//  metadata = {
//    "Email-Contact" = "%s" # Note metadata keys must be defined in Keyfactor
//  }
//}
//resource "keyfactor_certificate_deployment" "PFXCertificateDeployment" {
//	certificate_id = keyfactor_certificate.PFXCertificate.id
//	certificate_store_id = "%s"
//	certificate_alias = keyfactor_certificate.PFXCertificate.subject.subject_common_name
//}
//`, t.cn, t.o, t.l, t.c, t.ou, t.st, t.ipSans, t.dnsSans, t.keyPassword, t.ca, t.template, t.email, t.storeID)
//	return output
//}
