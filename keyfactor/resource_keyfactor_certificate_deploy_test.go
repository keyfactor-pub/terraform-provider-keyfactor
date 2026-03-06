package keyfactor

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateDeployResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	agentID, clientMachine := discoverAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)
	storePath := fmt.Sprintf("/tf-int-test-deploy-%d", time.Now().UnixNano())

	// Build cert config (enrollment pattern or template)
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var certConfig string
	if enrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca)
	} else {
		templateName := discoverTemplate(t, client)
		certConfig = testAccCertPFXConfig(templateName, ca)
	}

	storeConfig := testAccCertStoreConfig(storeType, clientMachine, agentID, storePath)
	deployConfig := testAccCertDeployConfig("keyfactor_certificate.test", "keyfactor_certificate_store.test")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certConfig + "\n" + storeConfig + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Certificate checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					// Store checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					// Deploy checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_deployment.test", "certificate_alias", "tf-int-test-deploy"),
				),
			},
		},
	})
}
