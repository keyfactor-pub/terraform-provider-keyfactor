package keyfactor

import (
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strings"
	"testing"
)

func TestAccKeyfactorStore_Basic(t *testing.T) {
	skipStore := testAccKeyfactorStoreCheckSkip()
	if skipStore {
		t.Skip("Skipping store acceptance tests (KEYFACTOR_SKIP_STORE_TESTS=true)")
	}

	t.Log("Note that this test doesn't care if the certificate store can be inventoried properly; it only cares ")
	t.Log("if the data going to/from Keyfactor is accurate within Terraform's expectations.")

	// Testing the store resource should only occur if the proper environment variables are set
	clientMachine, agentId := testAccKeyfactorStoreGetConfig(t)

	storePathPub := "~/terraform_pub.pem"
	storePathPriv := "~/terraform_priv.pem"

	certStoreType := "2"
	password := "TerraformAccTestBasic"
	inventoryMins := "60"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_store.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckKeyfactorStoreDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckKeyfactorStore_Basic(clientMachine, storePathPub, agentId, certStoreType, password, inventoryMins),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorStoreExists("keyfactor_store.test"),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.client_machine", clientMachine),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.store_path", storePathPub),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.cert_store_type", certStoreType),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.agent_id", agentId),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.inventory_schedule.0.interval.0.minutes", inventoryMins),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.password.0.value", password),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_store.test", "store.0.keyfactor_id"),
				),
			},
			{
				Config: testAccCheckKeyfactorStore_Modified(clientMachine, storePathPub, agentId, certStoreType, password, inventoryMins, storePathPriv),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorStoreExists("keyfactor_store.test"),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.client_machine", clientMachine),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.store_path", storePathPub),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.cert_store_type", certStoreType),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.agent_id", agentId),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.inventory_schedule.0.interval.0.minutes", inventoryMins),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.password.0.value", password),
					// Check computed values
					resource.TestCheckResourceAttrSet("keyfactor_store.test", "store.0.keyfactor_id"),
					// Check that the change propagated to new state
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.property.#", "2"),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.property.0.name", "separatePrivateKey"),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.property.0.value", "true"),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.property.1.name", "privateKeyPath"),
					resource.TestCheckResourceAttr("keyfactor_store.test", "store.0.property.1.value", storePathPriv),
				),
			},
		},
	})
}

func testAccKeyfactorStoreCheckSkip() bool {
	skipStoreTests := false
	if temp := os.Getenv("KEYFACTOR_SKIP_STORE_TESTS"); temp != "" {
		if strings.ToLower(temp) == "true" {
			skipStoreTests = true
		}
	}
	return skipStoreTests
}

func testAccKeyfactorStoreGetConfig(t *testing.T) (string, string) {
	var clientMachine, agentId string
	if clientMachine = os.Getenv("KEYFACTOR_CLIENT_MACHINE"); clientMachine == "" {
		t.Log("Note: Terraform Store Acceptance test tries to create a new PEM certificate store with the provided " +
			"orchestrator details. Ensure that this capability is supported.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_STORE_TESTS to true to skip Store resource acceptance tests")
		t.Fatal("KEYFACTOR_CLIENT_MACHINE must be set to perform store acceptance test")
	}

	if agentId = os.Getenv("KEYFACTOR_ORCHESTRATOR_AGENT_ID"); agentId == "" {
		t.Log("Note: Terraform Store Acceptance test tries to create a new PEM certificate store with the provided " +
			"orchestrator details. Ensure that this capability is supported.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_STORE_TESTS to true to skip Store resource acceptance tests")
		t.Fatal("KEYFACTOR_ORCHESTRATOR_AGENT_ID must be set to perform store acceptance test")
	}

	return clientMachine, agentId
}

func testAccCheckKeyfactorStoreDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "keyfactor_store" {
			continue
		}

		conn := testAccProvider.Meta().(*keyfactor.Client)
		var exists bool
		_, err := conn.GetCertificateStoreByID(rs.Primary.ID)
		if err != nil {
			// Should return an error if the cert doesn't exist, but let's analyze the error first to be sure
			// todo analyze the error
			exists = false
			break

			return err
		}
		if exists {
			return fmt.Errorf("resource still exists, ID: %s", rs.Primary.ID)
		}
	}
	return nil
}

func testAccCheckKeyfactorStoreExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("no store ID set")
		}

		conn := testAccProvider.Meta().(*keyfactor.Client)

		store, err := conn.GetCertificateStoreByID(rs.Primary.ID)
		if err != nil {
			return err
		}

		if store.Id == "" || store.StorePath == "" {
			return fmt.Errorf("store not found")
		}

		return nil
	}
}

func testAccCheckKeyfactorStore_Basic(clientMachine string, storePath string, agentId string, certStoreType string, password string, inventoryMins string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_store" "test" {
    store {
        client_machine  = "%s"
        store_path      = "%s"
        cert_store_type = %s
        inventory_schedule {
            interval {
                minutes = %s
            }
        }
        agent_id = "%s"
        password {
            value = "%s"
        }
    }
}
	`, clientMachine, storePath, certStoreType, inventoryMins, agentId, password)
}

func testAccCheckKeyfactorStore_Modified(clientMachine string, storePathPub string, agentId string, certStoreType string, password string, inventoryMins string, storePathPriv string) string {
	// Return the minimum (basic) required fields to enroll PRX certificate
	return fmt.Sprintf(`
	resource "keyfactor_store" "test" {
    store {
        client_machine  = "%s"
        store_path      = "%s"
        cert_store_type = %s
        inventory_schedule {
            interval {
                minutes = %s
            }
        }
        agent_id = "%s"
        password {
            value = "%s"
        }
		property {
			name  = "separatePrivateKey"
            value = "true"
		}
		property {
			name  = "privateKeyPath"
            value = "%s"
		}
    }
}
	`, clientMachine, storePathPub, certStoreType, inventoryMins, agentId, password, storePathPriv)
}
