package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

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
