package keyfactor

//
//import (
//	"fmt"
//	"github.com/spbsoluble/kfctl/api"
//	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
//	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
//	"log"
//	"os"
//	"strconv"
//	"strings"
//	"testing"
//)
//
//var pfxIdInt int
//
//func TestAccKeyfactorDeployCertificateBasic(t *testing.T) {
//	testAccKeyfactorCertificateDeployCheckSkip(t)
//
//	storeId1, storeId2 := testAccCheckKeyfactorDeployCertGetConfig(t)
//
//	err, _, pfx, password := enrollPFXCertificate(nil)
//	if err != nil {
//		t.Fatal(err)
//	}
//	pfxIdInt = pfx.KeyfactorID
//	pfxId := strconv.Itoa(pfx.KeyfactorID)
//	alias := strings.ToLower(pfx.Thumbprint)
//
//	resource.Test(t, resource.TestCase{
//		PreCheck:          func() { testAccPreCheck(t) },
//		IDRefreshName:     "keyfactor_deploy_certificate.test",
//		ProviderFactories: providerFactories,
//		CheckDestroy:      testAccKeyfactorDeployCertDestroy,
//		Steps: []resource.TestStep{
//			{
//				Config: testAccKeyfactorDeployCertificateBasic(pfxId, password),
//				Check: resource.ComposeTestCheckFunc(
//					// Check inputted values
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "certificate_id", pfxId),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "password", password),
//				),
//			},
//			// Add a certificate to the store
//			{
//				Config: testAccKeyfactorDeployCertificateModified(pfxId, password, storeId1, alias),
//				Check: resource.ComposeTestCheckFunc(
//					testAccCheckKeyfactorCertificateDeployed("keyfactor_deploy_certificate.test", storeId1, alias),
//					// Check inputted values
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "certificate_id", pfxId),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "password", password),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.#", "1"),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.certificate_store_id", storeId1),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.alias", alias),
//				),
//			},
//			// Add a second certificate to the store
//			{
//				Config: testAccKeyfactorDeployCertificateTwice(pfxId, password, storeId1, alias, storeId2, alias),
//				Check: resource.ComposeTestCheckFunc(
//					testAccCheckKeyfactorCertificateDeployed("keyfactor_deploy_certificate.test", storeId1, alias),
//					testAccCheckKeyfactorCertificateDeployed("keyfactor_deploy_certificate.test", storeId2, alias),
//					// Check inputted values
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "certificate_id", pfxId),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "password", password),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.#", "2"),
//					resource.TestCheckResourceAttrSet("keyfactor_deploy_certificate.test", "store.0.certificate_store_id"),
//					resource.TestCheckResourceAttrSet("keyfactor_deploy_certificate.test", "store.0.alias"),
//					resource.TestCheckResourceAttrSet("keyfactor_deploy_certificate.test", "store.1.certificate_store_id"),
//					resource.TestCheckResourceAttrSet("keyfactor_deploy_certificate.test", "store.1.alias"),
//				),
//			},
//			// Remove one of the stores
//			{
//				Config: testAccKeyfactorDeployCertificateModified(pfxId, password, storeId2, alias),
//				Check: resource.ComposeTestCheckFunc(
//					testAccCheckKeyfactorCertificateDeployed("keyfactor_deploy_certificate.test", storeId2, alias),
//					// Check inputted values
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "certificate_id", pfxId),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "password", password),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.#", "1"),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.certificate_store_id", storeId2),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.alias", alias),
//				),
//			},
//			// Switch from one store to another
//			{
//				Config: testAccKeyfactorDeployCertificateModified(pfxId, password, storeId1, alias),
//				Check: resource.ComposeTestCheckFunc(
//					testAccCheckKeyfactorCertificateDeployed("keyfactor_deploy_certificate.test", storeId1, alias),
//					// Check inputted values
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "certificate_id", pfxId),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "password", password),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.#", "1"),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.certificate_store_id", storeId1),
//					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.alias", alias),
//				),
//			},
//		},
//	})
//}
//
//func testAccCheckKeyfactorCertificateDeployed(name string, storeId string, alias string) resource.TestCheckFunc {
//	return func(s *terraform.State) error {
//		rs, ok := s.RootModule().Resources[name]
//		if !ok {
//			return fmt.Errorf("not found: %s", name)
//		}
//		if rs.Primary.ID == "" {
//			return fmt.Errorf("no resource ID set")
//		}
//
//		conn := testAccProvider.Meta().(*api.Client)
//		certId, err := strconv.Atoi(rs.Primary.ID)
//		if err != nil {
//			return err
//		}
//
//		args := &api.GetCertificateContextArgs{
//			IncludeLocations: boolToPointer(true),
//			Id:               certId,
//		}
//		certificateData, err := conn.GetCertificateContext(args)
//		if err != nil {
//			return err
//		}
//		locations := certificateData.Locations
//
//		for _, location := range locations {
//			log.Printf("Comparing %s to %s", storeId, location.CertStoreId)
//			log.Printf("Comparing %s to %s", alias, location.Alias)
//			if strings.EqualFold(location.CertStoreId, storeId) && strings.EqualFold(location.Alias, alias) {
//				return nil
//			} else {
//				log.Println("Determined not equal")
//			}
//		}
//
//		return fmt.Errorf("didn't find certificate with alias %s in store with ID %s", alias, storeId)
//	}
//}
//
//func testAccCheckKeyfactorDeployCertGetConfig(t *testing.T) (string, string) {
//	var store1, store2 string
//	if store1 = os.Getenv("KEYFACTOR_DEPLOY_CERT_STOREID1"); store1 == "" {
//		t.Log("Note: Terraform Deploy KfCertificate attempts to deploy a new PFX certificate to a certificate store that already exists in Keyfactor")
//		t.Log("Set an environment variable for KEYFACTOR_SKIP_DEPLOY_CERT_TESTS to 'true' to skip Deploy KfCertificate " +
//			"resource acceptance tests")
//		t.Fatal("KEYFACTOR_DEPLOY_CERT_STOREID1 must be set to perform Deploy KfCertificate acceptance tests")
//	}
//	if store2 = os.Getenv("KEYFACTOR_DEPLOY_CERT_STOREID2"); store2 == "" {
//		t.Log("Note: Terraform Deploy KfCertificate attempts to deploy a new PFX certificate to a certificate store that already exists in Keyfactor")
//		t.Log("Set an environment variable for KEYFACTOR_SKIP_DEPLOY_CERT_TESTS to 'true' to skip Deploy KfCertificate " +
//			"resource acceptance tests")
//		t.Fatal("KEYFACTOR_DEPLOY_CERT_STOREID2 must be set to perform Deploy KfCertificate acceptance tests")
//	}
//	return store1, store2
//}
//
//func testAccKeyfactorCertificateDeployCheckSkip(t *testing.T) {
//	if temp := os.Getenv("KEYFACTOR_SKIP_DEPLOY_CERT_TESTS"); temp != "" {
//		if strings.ToLower(temp) == "true" {
//			t.Skip("Skipping certificate deploy tests (KEYFACTOR_SKIP_DEPLOY_CERT_TESTS=true)")
//		}
//	}
//}
//
//func testAccKeyfactorDeployCertDestroy(s *terraform.State) error {
//	for _, rs := range s.RootModule().Resources {
//		if rs.Type != "keyfactor_attach_role" {
//			continue
//		}
//
//		certId, err := strconv.Atoi(rs.Primary.ID)
//		if err != nil {
//			return err
//		}
//
//		// Pull the provider metadata interface out of the testAccProvider provider
//		conn := testAccProvider.Meta().(*api.Client)
//
//		args := &api.GetCertificateContextArgs{
//			IncludeLocations: boolToPointer(true),
//			Id:               certId,
//		}
//		certificateData, err := conn.GetCertificateContext(args)
//		if err != nil {
//			return err
//		}
//		if len(certificateData.Locations) > 0 {
//			return fmt.Errorf("failed to remove certificate %d from all stores, still found in %d stores", certId, len(certificateData.Locations))
//		}
//		// If we get here, the relationship doesn't exist in Keyfactor
//		err = revokePFXCertificate(conn, pfxIdInt)
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}
//
//func testAccKeyfactorDeployCertificateBasic(certId string, password string) string {
//	return fmt.Sprintf(`
//	resource "keyfactor_deploy_certificate" "test" {
//		certificate_id = %s
//		password       = "%s"
//	}
//	`, certId, password)
//}
//
//func testAccKeyfactorDeployCertificateModified(certId string, password string, storeId string, alias string) string {
//	return fmt.Sprintf(`
//	resource "keyfactor_deploy_certificate" "test" {
//		certificate_id = %s
//		password       = "%s"
//		store {
//			certificate_store_id = "%s"
//			alias                = "%s"
//		}
//	}
//	`, certId, password, storeId, alias)
//}
//
//func testAccKeyfactorDeployCertificateTwice(certId string, password string, storeId1 string, alias1 string, storeId2 string, alias2 string) string {
//	return fmt.Sprintf(`
//	resource "keyfactor_deploy_certificate" "test" {
//		certificate_id = %s
//		password       = "%s"
//		store {
//			certificate_store_id = "%s"
//			alias                = "%s"
//		}
//		store {
//			certificate_store_id = "%s"
//			alias                = "%s"
//		}
//	}
//	`, certId, password, storeId1, alias1, storeId2, alias2)
//}
