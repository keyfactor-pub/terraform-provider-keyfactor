package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorCertificateStoreDataSource(t *testing.T) {
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate_store")
	var sID = os.Getenv("TEST_CERTIFICATE_STORE_ID")
	if sID == "" {
		sID = os.Getenv("KEYFACTOR_CERTIFICATE_STORE_ID")
		if sID == "" {
			sID = "1"
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorCertificateStoreBasic(sID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", sID),
					resource.TestCheckResourceAttrSet(resourceName, "store_path"),
					resource.TestCheckResourceAttrSet(resourceName, "store_type"),
					resource.TestCheckResourceAttrSet(resourceName, "approved"),
					resource.TestCheckResourceAttrSet(resourceName, "create_if_missing"),
					resource.TestCheckResourceAttrSet(resourceName, "properties.%"),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttrSet(resourceName, "agent_assigned"),
					resource.TestCheckResourceAttrSet(resourceName, "container_name"),
					//resource.TestCheckResourceAttrSet(resourceName, "inventory_schedule"), //TODO: Check this when implemented
					resource.TestCheckResourceAttrSet(resourceName, "set_new_password_allowed"),
					//resource.TestCheckResourceAttrSet(resourceName, "certificates.#"), //TODO: Check this when implemented
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorCertificateStoreBasic(resourceName string) string {
	return fmt.Sprintf(`
	data "keyfactor_certificate_store" "test" {
		id = "%s"
	}
	`, resourceName)
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes : no lab required)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateStoreDataSource tests the certificate store
// data source read path using pre-recorded HTTP cassettes.
//
// To record cassettes against a live lab:
//
//	RECORD_CASSETTES=1 make testunit
func TestUnitKeyfactorCertificateStoreDataSource(t *testing.T) {
	resourceName := "data.keyfactor_certificate_store.test"
	cassettePath := filepath.Join("testdata", "cassettes", "certificate_store_data_source")
	var storeType, clientMachine, agentID, storePath string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		// Recording mode: auto-discover lab resources and save params for replay.
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		// Use a K8S-compatible path format: namespace/name (no leading slash).
		storePath = "default/tf-unit-test-ds-1000001"
		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
		})
	} else {
		// Replay mode: load params recorded with the cassette.
		params := readStoreTestParams(cassettePath)
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
	}

	config := testAccCertStoreConfig(storeType, clientMachine, agentID, storePath) + "\n" +
		testAccCertStoreDataSourceByID("keyfactor_certificate_store.test")

	factories, cleanup := newVCRProviderFactories(t, "certificate_store_data_source")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttr(resourceName, "store_path", storePath),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttrSet(resourceName, "approved"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateStoreDataSourceByGUID tests lookup by GUID (id field).
func TestUnitKeyfactorCertificateStoreDataSourceByGUID(t *testing.T) {
	resourceName := "data.keyfactor_certificate_store.test_by_guid"
	cassetteName := "certificate_store_data_source_by_guid"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	var storeType, clientMachine, agentID, storePath string

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		storeType = discoverStoreTypeForAgent(t, client, agentID)
		storePath = fmt.Sprintf("default/tf-unit-ds-guid-%d", time.Now().UnixNano())
		writeStoreTestParams(cassettePath, storeTestParams{
			StoreType:     storeType,
			ClientMachine: clientMachine,
			AgentID:       agentID,
			StorePath:     storePath,
		})
	} else {
		params := readStoreTestParams(cassettePath)
		if params.StoreType == "" {
			t.Skip("No GUID data source cassette recorded. Run with RECORD_CASSETTES=1 against a live lab.")
		}
		storeType = params.StoreType
		clientMachine = params.ClientMachine
		agentID = params.AgentID
		storePath = params.StorePath
	}

	config := testAccCertStoreConfig(storeType, clientMachine, agentID, storePath) + "\n" +
		testAccCertStoreDataSourceByGUID("keyfactor_certificate_store.test")

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "client_machine"),
					resource.TestCheckResourceAttrSet(resourceName, "store_path"),
					resource.TestCheckResourceAttr(resourceName, "store_type", storeType),
					resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
					resource.TestCheckResourceAttrSet(resourceName, "approved"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateStoreDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)
	storeType := discoverStoreTypeForAgent(t, client, agentID)
	storePath := fmt.Sprintf("/tf-int-test-ds-%d", time.Now().UnixNano())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// First create a store, then read it back via data source
				Config: testAccCertStoreConfig(storeType, clientMachine, agentID, storePath) + "\n" +
					testAccCertStoreDataSourceByID("keyfactor_certificate_store.test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Resource checks
					resource.TestCheckResourceAttrSet("keyfactor_certificate_store.test", "id"),
					// Data source checks
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_store.test", "store_path"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_store.test", "store_type"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_store.test", "agent_id"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_store.test", "approved"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_store.test", "properties.%"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_store.test", "agent_assigned"),
				),
			},
		},
	})
}
