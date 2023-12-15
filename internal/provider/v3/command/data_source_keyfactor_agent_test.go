package command

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"os"
	"testing"
)

func TestAccKeyfactorAgentDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_agent")
	var aID = os.Getenv("TEST_AGENT_ID")
	var aCN = os.Getenv("TEST_AGENT_CLIENT_MACHINE_NAME")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				// Test lookup by ID
				Config: testAccDataSourceKeyfactorAgentBasic(t, aID),
				Check:  agentTestValidateAll(resourceName, aID),
			},
			{
				// Test lookup by empty ID
				Config:      testAccDataSourceKeyfactorAgentBasic(t, ""),
				Check:       agentTestValidateAll(resourceName, ""),
				ExpectError: invalidAgentRequestErrRegex,
			},
			{
				// Test lookup by client machine name
				Config: testAccDataSourceKeyfactorAgentBasic(t, aCN),
				Check:  agentTestValidateAll(resourceName, aCN),
			},
		},
	})
}

func testAccDataSourceKeyfactorAgentBasic(t *testing.T, resourceId string) string {
	output := fmt.Sprintf(`
	data "keyfactor_agent" "test" {
		agent_identifier = "%s"
	}
	`, resourceId)
	t.Logf("%s", output)
	return output
}

func agentTestValidateAll(resourceName string, resourceId string) resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(resourceName, "agent_id"),
		resource.TestCheckResourceAttrSet(resourceName, "agent_identifier"),
		resource.TestCheckResourceAttr(resourceName, "agent_identifier", resourceId),
		resource.TestCheckResourceAttrSet(resourceName, "agent_platform"),
		resource.TestCheckResourceAttrSet(resourceName, "auth_certificate_reenrollment"),
		resource.TestCheckResourceAttrSet(resourceName, "blueprint"),
		resource.TestCheckResourceAttrSet(resourceName, "capabilities.#"),
		resource.TestCheckResourceAttrSet(resourceName, "client_machine"),
		resource.TestCheckResourceAttrSet(resourceName, "id"),
		//resource.TestCheckResourceAttrSet(resourceName, "last_error_code"),
		resource.TestCheckResourceAttrSet(resourceName, "last_error_message"),
		resource.TestCheckResourceAttrSet(resourceName, "last_seen"),
		resource.TestCheckResourceAttrSet(resourceName, "last_thumbprint_used"),
		//resource.TestCheckResourceAttrSet(resourceName, "legacy_thumbprint"),
		resource.TestCheckResourceAttrSet(resourceName, "status"),
		//resource.TestCheckResourceAttrSet(resourceName, "thumbprint"),
		resource.TestCheckResourceAttrSet(resourceName, "username"),
		resource.TestCheckResourceAttrSet(resourceName, "version"),
	)
}
