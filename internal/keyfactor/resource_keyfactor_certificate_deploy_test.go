package keyfactor

import (
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAccKeyfactorDeployCertificateBasic(t *testing.T) {
	testAccKeyfactorCertificateDeployCheckSkip(t)

	storeId := testAccCheckKeyfactorDeployCertGetConfig(t)

	err, _, pfx, password := enrollPFXCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	pfxId := strconv.Itoa(pfx.KeyfactorID)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_deploy_certificate.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccKeyfactorDeployCertDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorDeployCertificateBasic(pfxId, password),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "certificate_id", pfxId),
					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "password", password),
				),
			},
			{
				Config: testAccKeyfactorDeployCertificateModified(pfxId, password, storeId, pfx.Thumbprint),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "certificate_id", pfxId),
					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "password", password),
					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.#", "1"),
					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.certificate_store_id", storeId),
					resource.TestCheckResourceAttr("keyfactor_deploy_certificate.test", "store.0.alias", pfx.Thumbprint),
				),
			},
		},
	})

}

func testAccCheckKeyfactorCertificateDeployed(name string, storeId string, alias string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("no resource ID set")
		}

		conn := testAccProvider.Meta().(*keyfactor.Client)
		certId, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}

		args := &keyfactor.GetCertificateContextArgs{
			IncludeLocations: boolToPointer(true),
			Id:               certId,
		}
		certificateData, err := conn.GetCertificateContext(args)
		if err != nil {
			return err
		}
		locations := certificateData.Locations

		for _, location := range locations {
			if location.CertStoreId == storeId && location.Alias == alias {
				return nil
			}
		}

		return fmt.Errorf("didn't find certificate with alias %s in store with ID %s", alias, storeId)
	}
}

func testAccCheckKeyfactorDeployCertGetConfig(t *testing.T) string {
	var store1 string
	if store1 = os.Getenv("KEYFACTOR_DEPLOY_CERT_STOREID1"); store1 == "" {
		t.Log("Note: Terraform Deploy Certificate attempts to deploy a new PFX certificate to a certificate store that already exists in Keyfactor")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_DEPLOY_CERT_TESTS to 'true' to skip Deploy Certificate " +
			"resource acceptance tests")
		t.Fatal("KEYFACTOR_DEPLOY_CERT_STOREID1 must be set to perform Deploy Certificate acceptance tests")
	}

	return store1
}

func testAccKeyfactorCertificateDeployCheckSkip(t *testing.T) {
	if temp := os.Getenv("KEYFACTOR_SKIP_DEPLOY_CERT_TESTS"); temp != "" {
		if strings.ToLower(temp) == "true" {
			t.Skip("Skipping certificate deploy tests (KEYFACTOR_SKIP_DEPLOY_CERT_TESTS=true)")
		}
	}
}

func testAccKeyfactorDeployCertDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "keyfactor_attach_role" {
			continue
		}

		certId, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return err
		}

		// Pull the provider metadata interface out of the testAccProvider provider
		conn := testAccProvider.Meta().(*keyfactor.Client)

		args := &keyfactor.GetCertificateContextArgs{
			IncludeLocations: boolToPointer(true),
			Id:               certId,
		}
		certificateData, err := conn.GetCertificateContext(args)
		if err != nil {
			return err
		}
		if len(certificateData.Locations) > 0 {
			return fmt.Errorf("failed to remove certificate %d from all stores, still found in %d stores", certId, len(certificateData.Locations))
		}
		// If we get here, the relationship doesn't exist in Keyfactor
	}
	return nil
}

func testAccKeyfactorDeployCertificateBasic(certId string, password string) string {
	return fmt.Sprintf(`
	resource "keyfactor_deploy_certificate" "test" {
		certificate_id = %s
		password       = "%s"
	}
	`, certId, password)
}

func testAccKeyfactorDeployCertificateModified(certId string, password string, storeId string, alias string) string {
	return fmt.Sprintf(`
	resource "keyfactor_deploy_certificate" "test" {
		certificate_id = %s
		password       = "%s"
		store {
			certificate_store_id = "%s"
			alias                = "%s"
		}
	}
	`, certId, password, storeId, alias)
}

func testAccKeyfactorDeployCertificateTwice(certId string, password string, storeId1 string, alias1 string, storeId2 string, alias2 string) string {
	return fmt.Sprintf(`
	resource "keyfactor_deploy_certificate" "test" {
		certificate_id = %s
		password       = "%s"
		store {
			certificate_store_id = "%s"
			alias                = "%s"
		}
		store {
			certificate_store_id = "%s"
			alias                = "%s"
		}
	}
	`, certId, password, storeId1, alias1, storeId2, alias2)
}
