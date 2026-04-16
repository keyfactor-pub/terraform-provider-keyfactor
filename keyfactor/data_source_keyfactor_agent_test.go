package keyfactor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorAgentDataSource tests the keyfactor_agent (singular) data
// source using VCR cassettes. Looks up an agent by GUID.
func TestUnitKeyfactorAgentDataSource(t *testing.T) {
	cassetteName := "agent_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var agentID, clientMachine string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		agentID, clientMachine = discoverAgent(t, client)
		writeAgentDataSourceTestParams(cassettePath, agentDataSourceTestParams{
			AgentID:       agentID,
			ClientMachine: clientMachine,
		})
	} else {
		params := readAgentDataSourceTestParams(cassettePath)
		if params.AgentID == "" {
			t.Skip("No agent params recorded; skipping")
		}
		agentID = params.AgentID
		clientMachine = params.ClientMachine
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dsName := "data.keyfactor_agent.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentDataSourceConfig(agentID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "agent_id", agentID),
					resource.TestCheckResourceAttr(dsName, "client_machine", clientMachine),
					resource.TestCheckResourceAttr(dsName, "status", "2"),
					resource.TestCheckResourceAttrSet(dsName, "version"),
					resource.TestCheckResourceAttrWith(dsName, "capabilities.#", func(value string) error {
						if value == "0" {
							return nil // some agents may have no capabilities listed
						}
						return nil
					}),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorAgentDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)

	// Test 1: Look up by GUID
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentDataSourceConfig(agentID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_agent.test", "agent_id", agentID),
					resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "client_machine"),
					resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "status"),
					resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "version"),
					resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "capabilities.#"),
				),
			},
		},
	})

	// Test 2: Look up by client machine name
	if clientMachine != "" {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccAgentDataSourceConfig(clientMachine),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "id"),
						resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "agent_id"),
						resource.TestCheckResourceAttr("data.keyfactor_agent.test", "client_machine", clientMachine),
						resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "status"),
						resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "version"),
						resource.TestCheckResourceAttrSet("data.keyfactor_agent.test", "capabilities.#"),
					),
				},
			},
		})
	}
}
