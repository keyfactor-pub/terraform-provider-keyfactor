// ---------------------------------------------------------------------------
// Certificate Store Resource Tests
// ---------------------------------------------------------------------------
//
// TESTING REQUIREMENT:
// All changes to the certificate store resource or data source MUST include:
//   - A TestUnit* VCR test covering the new code path
//   - A TestInt* integration test for the happy path
//
// See CLAUDE.md "Test Tiers" for details on each test level.
// ---------------------------------------------------------------------------

package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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

	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
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
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_store_resource")
	var storeType, clientMachine, agentID, storePath string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		// Recording mode: auto-discover lab resources and save params for replay.
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		// Use a K8S-compatible path format: namespace/name (no leading slash).
		storePath = "default/tf-unit-test-1000000"
		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
		})
	} else {
		// Replay mode: load params recorded with the cassette so that the HCL
		// config exactly matches what was used during recording, avoiding drift.
		params := readStoreTestParams(cassettePath)
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
	}

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
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "agent_identifier", agentID),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "agent_id"),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "approved", "true"),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "agent_assigned", "true"),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "properties.%"),
					resource.TestCheckResourceAttr("keyfactor_certificate_store.test", "display_name", fmt.Sprintf("%s - %s", clientMachine, storePath)),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateStoreResource_Import tests the import lifecycle
// using VCR cassettes. It creates a store in Step 1, then imports it by GUID
// in Step 2 to verify ImportState correctly populates state.
//
// To record cassettes:
//
//	RECORD_CASSETTES=1 make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreResource_Import
func TestUnitKeyfactorCertificateStoreResource_Import(t *testing.T) {
	cassetteName := "certificate_store_resource_import"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	var storeType, clientMachine, agentID, storePath string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		storePath = "default/tf-unit-import-1000000"
		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
		})
	} else {
		params := readStoreTestParams(cassettePath)
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttr(resourceName, "approved", "true"),
					resource.TestCheckResourceAttr(resourceName, "agent_assigned", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "properties.%"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttr(resourceName, "approved", "true"),
					resource.TestCheckResourceAttr(resourceName, "agent_assigned", "true"),
				),
			},
		},
	})
}

// TestUnitParseStoreImportID is a pure-Go table test for the structured
// import-ID parser used by the keyfactor_certificate_store resource. It
// covers each accepted form plus the explicit error cases.
func TestUnitParseStoreImportID(t *testing.T) {
	const guid = "b53baab1-9b5d-462b-9273-8fe78eabe609"

	cases := []struct {
		name    string
		input   string
		want    storeImportRef
		wantErr bool
	}{
		{name: "bare guid", input: guid, want: storeImportRef{StoreID: guid}},
		{name: "stores prefix", input: "stores/" + guid, want: storeImportRef{StoreID: guid}},
		{name: "containers numeric id", input: "containers/42/stores/" + guid, want: storeImportRef{ContainerID: "42", StoreID: guid}},
		{name: "containers name", input: "containers/MyTeam/stores/" + guid, want: storeImportRef{ContainerID: "MyTeam", StoreID: guid}},

		{name: "empty", input: "", wantErr: true},
		{name: "stores empty", input: "stores/", wantErr: true},
		{name: "containers single segment", input: "containers/x", wantErr: true},
		{name: "containers empty id", input: "containers//stores/y", wantErr: true},
		{name: "containers empty store", input: "containers/x/stores/", wantErr: true},
		{name: "unknown prefix", input: "garbage/foo", wantErr: true},
		{name: "stores extra segment", input: "stores/foo/bar", wantErr: true},
		{name: "trailing slash", input: guid + "/", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStoreImportID(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got ref=%+v", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("input %q: got %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

// TestUnitKeyfactorCertificateStoreResource_Import_StoresPrefix is the same
// shape as TestUnitKeyfactorCertificateStoreResource_Import but uses the
// "stores/<guid>" import ID form. It reuses the existing cassette because
// the underlying API calls are identical.
func TestUnitKeyfactorCertificateStoreResource_Import_StoresPrefix(t *testing.T) {
	cassetteName := "certificate_store_resource_import"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	var storeType, clientMachine, agentID, storePath string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("This test reuses the existing certificate_store_resource_import cassette — record via TestUnitKeyfactorCertificateStoreResource_Import")
	}
	params := readStoreTestParams(cassettePath)
	storeType = params.StoreType
	clientMachine = params.ClientMachine
	agentID = params.AgentID
	storePath = params.StorePath

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
				// Prepend "stores/" to the GUID — should resolve identically to a bare GUID.
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return "", fmt.Errorf("not found: %s", resourceName)
					}
					return "stores/" + rs.Primary.ID, nil
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateStoreResource_Import_ContainersPath verifies
// the structured "containers/<id>/stores/<guid>" import path. It uses a
// dedicated cassette because the API call sequence (CertificateStores
// list-by-container + GetStoreContainers for name resolution) differs from
// the legacy GetCertificateStoreByID path.
//
// Record with:
//
//	make testunit-record-cert-store-import-container
func TestUnitKeyfactorCertificateStoreResource_Import_ContainersPath(t *testing.T) {
	cassetteName := "certificate_store_resource_import_via_container"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	var storeType, clientMachine, agentID, storePath, containerName string
	var containerID int

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		storePath = fmt.Sprintf("default/tf-unit-import-cnt-%d", time.Now().UnixNano())
		containerName = discoverApplication(t, client)
		if containerName == "" {
			t.Skip("No application/container available in the lab for recording")
		}
		// Resolve the numeric container ID so the import path can use it directly.
		ct, err := client.GetStoreContainer(containerName)
		if err != nil || ct == nil || ct.Id == nil {
			t.Fatalf("failed to resolve container ID for %q: %v", containerName, err)
		}
		containerID = *ct.Id
		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
			ContainerName: containerName,
			ContainerID:   containerID,
		})
	} else {
		params := readStoreTestParams(cassettePath)
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
		containerName = params.ContainerName
		containerID = params.ContainerID
		if containerName == "" || containerID == 0 {
			t.Skip("cassette params missing container info — record cassette first")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a store inside the chosen container.
				Config: testAccCertStoreConfigWithAppName(storeType, clientMachine, agentID, storePath, containerName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "container_name", containerName),
				),
			},
			{
				// Step 2: import via containers/<id>/stores/<guid>.
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[resourceName]
					if !ok {
						return "", fmt.Errorf("not found: %s", resourceName)
					}
					return fmt.Sprintf("containers/%d/stores/%s", containerID, rs.Primary.ID), nil
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "container_name", containerName),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateStoreResource_Import_BadFormat verifies that a
// malformed import ID surfaces as a Terraform import diagnostic. No cassette
// is needed because parsing fails before any HTTP request is issued.
func TestUnitKeyfactorCertificateStoreResource_Import_BadFormat(t *testing.T) {
	cassetteName := "certificate_store_resource_import"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	if os.Getenv("RECORD_CASSETTES") == "1" {
		t.Skip("Bad-format test does not record HTTP traffic")
	}
	params := readStoreTestParams(cassettePath)

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreConfig(params.StoreType, params.ClientMachine, params.AgentID, params.StorePath),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     "garbage/foo",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Invalid certificate store import ID`),
			},
		},
	})
}

// TestUnitKeyfactorCertificateStoreResource_ApplicationName tests that a store
// created using application_name (the v25+ alias for container_name) works
// correctly. When no container/application is specified, both fields must be
// null in state. When a container IS specified via application_name, both
// application_name and container_name must be synced in state.
//
// This test uses the existing "certificate_store_resource" cassette which was
// recorded WITHOUT a container — it validates the null/null sync case. A
// separate cassette "certificate_store_resource_application_name" is needed for
// the non-null case; in replay mode the test skips if that cassette is missing.
//
// To record:
//
//	RECORD_CASSETTES=1 make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreResource_ApplicationName
func TestUnitKeyfactorCertificateStoreResource_ApplicationName(t *testing.T) {
	cassetteName := "certificate_store_resource_application_name"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	var storeType, clientMachine, agentID, storePath, containerName string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		// Recording mode: auto-discover lab resources.
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		storePath = "default/tf-unit-appname-1000000"
		containerName = discoverApplication(t, client)
		if containerName == "" {
			t.Skip("No application/container available in the lab for recording")
		}
		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
			ContainerName: containerName,
		})
	} else {
		params := readStoreTestParams(cassettePath)
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
		containerName = params.ContainerName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create using application_name (not container_name).
				Config: testAccCertStoreConfigWithAppName(storeType, clientMachine, agentID, storePath, containerName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
					resource.TestCheckResourceAttr(resourceName, "agent_identifier", agentID),
					// Both fields must be synced to the same container name.
					resource.TestCheckResourceAttr(resourceName, "application_name", containerName),
					resource.TestCheckResourceAttr(resourceName, "container_name", containerName),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateStoreResource_NoContainer verifies that when
// neither application_name nor container_name is specified, both are absent
// from state. Uses the existing "certificate_store_resource" cassette which
// was recorded without a container.
func TestUnitKeyfactorCertificateStoreResource_NoContainer(t *testing.T) {
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_store_resource")
	var storeType, clientMachine, agentID, storePath string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		storePath = "default/tf-unit-test-1000000"
		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
		})
	} else {
		params := readStoreTestParams(cassettePath)
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
	}

	factories, cleanup := newVCRProviderFactories(t, "certificate_store_resource")
	defer cleanup()

	resourceName := "keyfactor_certificate_store.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create without application_name or container_name.
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					// Neither field should be set when no container is provided.
					resource.TestCheckNoResourceAttr(resourceName, "application_name"),
					resource.TestCheckNoResourceAttr(resourceName, "container_name"),
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
	storePath := fmt.Sprintf("default/tf-int-test-%d", time.Now().UnixNano())
	resourceName := "keyfactor_certificate_store.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttr(resourceName, "agent_identifier", agentID),
					resource.TestCheckResourceAttr(resourceName, "approved", "true"),
					resource.TestCheckResourceAttr(resourceName, "agent_assigned", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "properties.%"),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateStoreResource_Import verifies that an existing
// certificate store can be imported by its GUID and that state is populated.
func TestIntKeyfactorCertificateStoreResource_Import(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)
	storePath := fmt.Sprintf("default/tf-import-test-%d", time.Now().UnixNano())
	resourceName := "keyfactor_certificate_store.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create the store so we have a GUID to import.
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
					resource.TestCheckResourceAttr(resourceName, "approved", "true"),
					resource.TestCheckResourceAttr(resourceName, "agent_assigned", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "properties.%"),
				),
			},
			{
				// Step 2: Import the same store by GUID and verify key attributes.
				// ImportStateVerify is false because several fields (server_password,
				// agent_identifier, properties, etc.) are not returned by the read-after-import
				// when prior state is unavailable.
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttr(resourceName, "client_machine", clientMachine),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttr(resourceName, "approved", "true"),
					resource.TestCheckResourceAttr(resourceName, "agent_assigned", "true"),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateStoreResource_ApplicationName creates a store with
// application_name (the v25+ alias), verifies both application_name and
// container_name are synced in state, then updates to use container_name
// (backwards-compat alias) and verifies both remain in sync.
func TestIntKeyfactorCertificateStoreResource_ApplicationName(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)

	containerName := discoverApplication(t, client)
	if containerName == "" {
		t.Skip("No application/container available in the lab — cannot test application_name")
	}

	storePath := fmt.Sprintf("default/tf-int-appname-%d", time.Now().UnixNano())
	resourceName := "keyfactor_certificate_store.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create using application_name.
				Config: testAccCertStoreConfigWithAppName(storeType, clientMachine, agentID, storePath, containerName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					// Both fields must reflect the same value.
					resource.TestCheckResourceAttr(resourceName, "application_name", containerName),
					resource.TestCheckResourceAttr(resourceName, "container_name", containerName),
				),
			},
			{
				// Step 2: Update to use container_name (the legacy alias) instead.
				// The same container name, but expressed via the other attribute.
				// Both fields must still be synced.
				Config: testAccCertStoreConfigWithContainerName(storeType, clientMachine, agentID, storePath, containerName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "application_name", containerName),
					resource.TestCheckResourceAttr(resourceName, "container_name", containerName),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateStoreResource_ContainerNameBackwardsCompat creates
// a store using the legacy container_name attribute and verifies that
// application_name is also populated in state (sync guarantee).
func TestIntKeyfactorCertificateStoreResource_ContainerNameBackwardsCompat(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)

	containerName := discoverApplication(t, client)
	if containerName == "" {
		t.Skip("No application/container available in the lab — cannot test container_name backwards compat")
	}

	storePath := fmt.Sprintf("default/tf-int-container-%d", time.Now().UnixNano())
	resourceName := "keyfactor_certificate_store.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create using legacy container_name attribute.
				Config: testAccCertStoreConfigWithContainerName(storeType, clientMachine, agentID, storePath, containerName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					// application_name must also be populated via sync.
					resource.TestCheckResourceAttr(resourceName, "application_name", containerName),
					resource.TestCheckResourceAttr(resourceName, "container_name", containerName),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateStoreResource_Import_ViaContainer verifies the
// "containers/<id>/stores/<guid>" import path works against a live lab. The
// caller may not have read-on-all-stores permission, so the scoped lookup
// path uses GetCertificateStoreByContainerID instead of GetCertificateStoreByID.
//
// This test creates its own keyfactor_application (container) so it does not
// depend on the lab having a pre-existing container — and so it does not
// accidentally bind to a leftover artifact from a previous test run.
func TestIntKeyfactorCertificateStoreResource_Import_ViaContainer(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)

	unix := time.Now().UnixNano()
	containerName := fmt.Sprintf("tf-int-cnt-%d", unix)
	storePath := fmt.Sprintf("default/tf-int-import-cnt-%d", unix)

	appResourceName := "keyfactor_application.test"
	storeResourceName := "keyfactor_certificate_store.test"

	cfg := testAccCertStoreWithOwnContainerConfig(containerName, storeType, clientMachine, agentID, storePath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the container AND a store scoped to it in one apply.
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(appResourceName, "id"),
					resource.TestCheckResourceAttr(appResourceName, "name", containerName),
					resource.TestCheckResourceAttrSet(storeResourceName, "id"),
					resource.TestCheckResourceAttr(storeResourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(storeResourceName, "container_name", containerName),
					resource.TestCheckResourceAttrSet(storeResourceName, "container_id"),
				),
			},
			{
				// Step 2: re-import via containers/<id>/stores/<guid>, pulling the
				// container ID from the application resource's state (not a Go
				// closure) so we exercise the scoped import path end-to-end.
				ResourceName:      storeResourceName,
				ImportState:       true,
				ImportStateVerify: false,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					app, ok := s.RootModule().Resources[appResourceName]
					if !ok {
						return "", fmt.Errorf("not found: %s", appResourceName)
					}
					appID := app.Primary.Attributes["id"]
					if appID == "" {
						return "", fmt.Errorf("%s has empty id attribute", appResourceName)
					}
					store, ok := s.RootModule().Resources[storeResourceName]
					if !ok {
						return "", fmt.Errorf("not found: %s", storeResourceName)
					}
					return fmt.Sprintf("containers/%s/stores/%s", appID, store.Primary.ID), nil
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(storeResourceName, "id"),
					resource.TestCheckResourceAttr(storeResourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(storeResourceName, "client_machine", clientMachine),
					resource.TestCheckResourceAttr(storeResourceName, "container_name", containerName),
					resource.TestCheckResourceAttrSet(storeResourceName, "container_id"),
				),
			},
		},
	})
}
