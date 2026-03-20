package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

func TestUnitKeyfactorCertificateDeployResource(t *testing.T) {
	cassetteName := "certificate_deploy_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var params deployTestParams
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		agentID, clientMachine := discoverAgent(t, client)
		storeType := discoverStoreTypeForAgent(t, client, agentID)

		var storePath string
		if strings.HasPrefix(strings.ToLower(storeType), "k8s") {
			if k8sStoreCredentials() == "" {
				t.Skip("Skipping K8S deploy test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
			}
			storePath = fmt.Sprintf("default/tf-unit-deploy-%d", time.Now().UnixNano())
		} else {
			storePath = fmt.Sprintf("/tf-unit-deploy-%d", time.Now().UnixNano())
		}

		ca := discoverCA(t, client)
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern == "" {
			templateName = discoverTemplate(t, client)
		}
		cn := randomTestCN("tf-unit-deploy")

		params = deployTestParams{
			CN:                cn,
			StoreType:         storeType,
			ClientMachine:     clientMachine,
			AgentID:           agentID,
			StorePath:         storePath,
			CAName:            ca,
			TemplateName:      templateName,
			EnrollmentPattern: enrollmentPattern,
		}
		writeDeployTestParams(cassettePath, params)
	} else {
		params = readDeployTestParams(cassettePath)
		if params.CN == "" {
			t.Skip("No deploy cassette recorded. Run with RECORD_CASSETTES=1 against a live lab with an agent.")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	var certConfig string
	if params.EnrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(params.EnrollmentPattern, params.CAName, params.CN)
	} else {
		certConfig = testAccCertPFXConfig(params.TemplateName, params.CAName, params.CN)
	}
	storeConfig := testAccCertStoreConfig(params.StoreType, params.ClientMachine, params.AgentID, params.StorePath)
	deployConfig := testAccCertDeployConfig("keyfactor_certificate.test", "keyfactor_certificate_store.test")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: certConfig + "\n" + storeConfig + "\n" + deployConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_deployment.test", "certificate_store_id"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateDeployResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	ca := discoverCA(t, client)
	agentID, clientMachine := discoverAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)

	// For K8S store types, require credentials and use namespace/name path format
	var storePath string
	if strings.HasPrefix(strings.ToLower(storeType), "k8s") {
		if k8sStoreCredentials() == "" {
			t.Skip("Skipping K8S deployment test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
		}
		storePath = fmt.Sprintf("default/tf-int-test-deploy-%d", time.Now().UnixNano())
	} else {
		storePath = fmt.Sprintf("/tf-int-test-deploy-%d", time.Now().UnixNano())
	}

	// Build cert config (enrollment pattern or template)
	cn := randomTestCN("tf-int-deploy")
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	var certConfig string
	if enrollmentPattern != "" {
		certConfig = testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn)
	} else {
		templateName := discoverTemplate(t, client)
		certConfig = testAccCertPFXConfig(templateName, ca, cn)
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
				),
			},
		},
	})
}
