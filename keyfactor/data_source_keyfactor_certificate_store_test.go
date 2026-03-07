package keyfactor

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorCertificateStoreDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate_store")
	var sID = os.Getenv("TEST_CERTIFICATE_STORE_ID")
	if sID == "" {
		sID = os.Getenv("KEYFACTOR_CERTIFICATE_STORE_ID")
		if sID == "" {
			sID = "1"
		}
	}
	var sPass = os.Getenv("KEYFACTOR_CERTIFICATE_STORE_PASS")
	if sPass == "" {
		sPass = os.Getenv("TEST_CERTIFICATE_STORE_PASS")
		if sPass == "" {
			sPass = "password1234!"
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorCertificateStoreBasic(sID, sPass),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", sID),
					resource.TestCheckResourceAttr(resourceName, "password", sPass),
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

func testAccDataSourceKeyfactorCertificateStoreBasic(resourceName string, password string) string {
	return fmt.Sprintf(`
	data "keyfactor_certificate_store" "test" {
		id = "%s"
		password = "%s"
	}
	`, resourceName, password)
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes — no lab required)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateStoreDataSource tests the certificate store
// data source read path using pre-recorded HTTP cassettes.
//
// To record cassettes against a live lab:
//
//	KEYFACTOR_CERTIFICATE_STORE_ID=<uuid> RECORD_CASSETTES=1 make testunit
func TestUnitKeyfactorCertificateStoreDataSource(t *testing.T) {
	// The store ID and client_machine/store_path must match cassette values.
	storeID := envOrDefault("KEYFACTOR_CERTIFICATE_STORE_ID", "vcr-store-id")
	resourceName := "data.keyfactor_certificate_store.test"

	factories, cleanup := newVCRProviderFactories(t, "certificate_store_data_source")
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceKeyfactorCertificateStoreBasic(storeID, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "store_path"),
					resource.TestCheckResourceAttrSet(resourceName, "store_type"),
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
