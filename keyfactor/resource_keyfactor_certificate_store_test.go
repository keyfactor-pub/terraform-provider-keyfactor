package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"os"
	"testing"
	"time"
)

type certificateStoreTestCase_v9 struct {
	orchestrator string
	storePath    string
	agentId      string
	storeType    string
	schedule     string
	containerId  int
	password     string
	resourceName string
}

type certificateStoreTestCase struct {
	clientMachine   string
	storePath       string
	agentIdentifier string
	storeType       string
	properties      map[string]interface{}
	schedule        string
	containerName   string
	serverUserName  string
	serverPassword  string
	storePassword   string
	serverUseSSL    bool
	resourceName    string
}

func TestAccKeyfactorCertificateStoreResource(t *testing.T) {

	r := certificateStoreTestCase{
		clientMachine:   os.Getenv("KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE"),
		storePath:       os.Getenv("KEYFACTOR_CERTIFICATE_STORE_PATH"),
		agentIdentifier: os.Getenv("KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID"),
		storeType:       os.Getenv("KEYFACTOR_CERTIFICATE_STORE_TYPE"),
		containerName:   os.Getenv("KEYFACTOR_CERTIFICATE_STORE_CONTAINER_NAME1"),
		serverUserName:  os.Getenv("TEST_SERVER_USERNAME"),
		serverPassword:  os.Getenv("TEST_SERVER_PASSWORD"),
		storePassword:   "",
		schedule:        "",
		serverUseSSL:    true,
		resourceName:    "keyfactor_certificate_store.tf_acc_test",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorCertificateStoreResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "store_path"),     // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "store_type"),     // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "client_machine"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "agent_id"),       // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "password"),       // TODO: Check specific value
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
			//{
			//	Config: testAccKeyfactorCertificateStoreResourceConfig(r2),
			//	Check: resource.ComposeAggregateTestCheckFunc(
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "id"),
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "store_path"),         // TODO: Check specific value
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "store_type"),         // TODO: Check specific value
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "client_machine"),     // TODO: Check specific value
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "agent_id"),           // TODO: Check specific value
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "inventory_schedule"), // TODO: Check specific value
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "container_id"),       // TODO: Check specific value
			//		resource.TestCheckResourceAttrSet(r2.resourceName, "password"),           // TODO: Check specific value
			//	),
			//},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccKeyfactorCertificateStoreResourceConfig(t certificateStoreTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_certificate_store" "tf_k8s_acc_test" {
  client_machine = "%s" # Orchestrator client name
  store_path     = "%s" # Varies based on store type
  agent_identifier = "%s" # Orchestrator GUID
  store_type     = "%s" # Must exist in KeyFactor
  properties = {
    # Optional properties based on the store type
  }
  inventory_schedule = "%s" # How often to update the inventory
  container_name       = "%s"   # ID of the KeyFactor container
  store_password           = "%s"
  server_username          = "%s" # The username for the certificate store.
  server_password          = "%s" # The password for the certificate store. Note: This is bad practice, use TF_VAR_<variable_name> instead.
  server_use_ssl           = true
  # The password for the certificate store. Note: This is bad practice, use TF_VAR_<variable_name> instead.
}
`, t.clientMachine, t.storePath, t.agentIdentifier, t.storeType, t.schedule, t.containerName, t.storePassword, t.serverUserName, t.serverPassword)
	return output
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes — no lab required)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateStoreResource tests the full create/read/destroy
// lifecycle of a certificate store resource using pre-recorded HTTP cassettes.
//
// To record cassettes against a live lab:
//
//	RECORD_CASSETTES=1 make testunit
func TestUnitKeyfactorCertificateStoreResource(t *testing.T) {
	// These values must match what was used when recording the cassette.
	storeType := envOrDefault("KEYFACTOR_CERTIFICATE_STORE_TYPE", "SSL")
	clientMachine := envOrDefault("KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE", "vcr-test-machine")
	agentID := envOrDefault("KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID", "vcr-agent-id")
	storePath := envOrDefault("KEYFACTOR_CERTIFICATE_STORE_PATH", "/vcr-test-store")

	factories, cleanup := newVCRProviderFactories(t, "certificate_store_resource")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "store_path", storePath),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "store_type", storeType),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "client_machine", clientMachine),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "agent_id"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "approved"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery, only need lab connection env vars)
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateStoreResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)

	// Use a store type from the agent's capabilities for best compatibility
	storeType := discoverStoreTypeForAgent(t, client, agentID)
	storePath := fmt.Sprintf("/tf-int-test-%d", time.Now().UnixNano())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "store_path", storePath),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "store_type", storeType),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "client_machine", clientMachine),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "agent_id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "agent_identifier", agentID),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "approved"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "properties.%"),
				),
			},
		},
	})
}
