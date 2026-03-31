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

// TestUnitKeyfactorCertificateDeployResource_NoInvSchedule verifies that
// deploying a certificate to a store that has NO inventory schedule configured
// succeeds with a warning and skips the validateDeployment polling loop.
//
// The cassette must capture a GetCertificateStoreByID response where all
// InventorySchedule sub-fields (Immediate, Interval, Daily, ExactlyOnce) are
// nil/absent. Use a K8SPKCS12 store for recording — it exhibits this behavior
// by default unless an inventory_schedule is explicitly configured.
//
// To record: RECORD_CASSETTES=1 go test -run TestUnitKeyfactorCertificateDeployResource_NoInvSchedule -v
// (or: make testunit-record-cert-deploy-no-inv)
func TestUnitKeyfactorCertificateDeployResource_NoInvSchedule(t *testing.T) {
	cassetteName := "certificate_deploy_resource_no_inv_schedule"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var params deployTestParams
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		agentID, clientMachine := discoverAgent(t, client)

		// Use K8SPKCS12 specifically — it requires a separate inventory job,
		// so stores created without inventory_schedule trigger the warning path.
		storeType := "K8SPKCS12"
		if k8sStoreCredentials() == "" {
			t.Skip("Skipping no-inv-schedule deploy test: set KEYFACTOR_K8S_CREDENTIALS_FILE or KEYFACTOR_K8S_SERVER_PASSWORD")
		}
		storePath := fmt.Sprintf("default/tf-unit-deploy-noinv-%d", time.Now().UnixNano())

		ca := discoverCA(t, client)
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		var templateName string
		if enrollmentPattern == "" {
			templateName = discoverTemplate(t, client)
		}
		cn := randomTestCN("tf-unit-deploy-noinv")

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
			t.Skip("No no-inv-schedule deploy cassette recorded. Run: make testunit-record-cert-deploy-no-inv")
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
	// Store config without inventory_schedule — triggers the no-inv-schedule warning path.
	storeConfig := testAccCertStoreConfig(params.StoreType, params.ClientMachine, params.AgentID, params.StorePath)
	deployConfig := testAccCertDeployConfig("keyfactor_certificate.test", "keyfactor_certificate_store.test")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// The deployment must succeed (no error) even though the store has no
				// inventory schedule. A non-fatal warning is emitted instead.
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
