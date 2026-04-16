package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestIntKeyfactorAgentsDataSource verifies the keyfactor_agents (plural) data
// source returns a list of agents and supports filtering. (Fixes #52)
func TestIntKeyfactorAgentsDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	agentID, clientMachine := discoverAgent(t, client)

	// Test 1: No filters — should return at least one agent
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentsDataSourceConfigNoFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_agents.test", "id"),
					resource.TestCheckResourceAttrWith("data.keyfactor_agents.test", "agents.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one agent, got 0")
						}
						return nil
					}),
				),
			},
		},
	})

	// Test 2: Filter by status=2 (Approved) — the discovered agent should be present
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentsDataSourceConfigStatus(2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrWith("data.keyfactor_agents.test", "agents.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one approved agent, got 0")
						}
						return nil
					}),
					resource.TestCheckResourceAttr("data.keyfactor_agents.test", "agents.0.status", "2"),
				),
			},
		},
	})

	// Test 3: Filter by client machine name
	if clientMachine != "" {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccAgentsDataSourceConfigClientMachine(clientMachine),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrWith("data.keyfactor_agents.test", "agents.#", func(value string) error {
							if value == "0" {
								return fmt.Errorf("expected at least one agent matching machine %q, got 0", clientMachine)
							}
							return nil
						}),
					),
				},
			},
		})
	}

	// Test 4: Filter by a capability the discovered agent has
	agents, err := client.GetAgentList()
	if err == nil {
		for _, a := range agents {
			if a.AgentId == agentID && len(a.Capabilities) > 0 {
				cap := a.Capabilities[0]
				t.Logf("Testing capability filter with: %s", cap)
				resource.Test(t, resource.TestCase{
					ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
					Steps: []resource.TestStep{
						{
							Config: testAccAgentsDataSourceConfigCapability(cap),
							Check: resource.ComposeAggregateTestCheckFunc(
								resource.TestCheckResourceAttrWith("data.keyfactor_agents.test", "agents.#", func(value string) error {
									if value == "0" {
										return fmt.Errorf("expected at least one agent with capability %q, got 0", cap)
									}
									return nil
								}),
							),
						},
					},
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorAgentsDataSource verifies the keyfactor_agents (plural) data
// source using VCR cassettes. (Fixes #52)
func TestUnitKeyfactorAgentsDataSource(t *testing.T) {
	cassetteName := "agents_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		// Just verify we can list agents — params file not needed for this data source
		agents, err := client.GetAgentList()
		if err != nil {
			t.Fatalf("Failed to list agents: %s", err)
		}
		if len(agents) == 0 {
			t.Skip("No agents available in lab for recording")
		}
		t.Logf("Recording with %d agents available", len(agents))
		// Write a minimal params file so replay knows the cassette exists
		writeAgentsTestParams(cassettePath, agentsTestParams{
			AgentCount: len(agents),
		})
	} else {
		params := readAgentsTestParams(cassettePath)
		if params.AgentCount == 0 {
			t.Skip("No agents params file or zero agents recorded; skipping")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentsDataSourceConfigNoFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_agents.test", "id"),
					resource.TestCheckResourceAttrWith("data.keyfactor_agents.test", "agents.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one agent, got 0")
						}
						return nil
					}),
				),
			},
			{
				Config: testAccAgentsDataSourceConfigStatus(2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrWith("data.keyfactor_agents.test", "agents.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one approved agent, got 0")
						}
						return nil
					}),
					resource.TestCheckResourceAttr("data.keyfactor_agents.test", "agents.0.status", "2"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// HCL config generators
// ---------------------------------------------------------------------------

func testAccAgentsDataSourceConfigNoFilter() string {
	return `
data "keyfactor_agents" "test" {
}
`
}

func testAccAgentsDataSourceConfigStatus(status int) string {
	return fmt.Sprintf(`
data "keyfactor_agents" "test" {
  status_filter = %d
}
`, status)
}

func testAccAgentsDataSourceConfigClientMachine(machine string) string {
	return fmt.Sprintf(`
data "keyfactor_agents" "test" {
  client_machine_filter = "%s"
}
`, machine)
}

func testAccAgentsDataSourceConfigCapability(capability string) string {
	return fmt.Sprintf(`
data "keyfactor_agents" "test" {
  capability_filter = "%s"
}
`, capability)
}
