package keyfactor

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"os"
	"strconv"
	"testing"
)

type certificateStoreTestCase struct {
	orchestrator string
	storePath    string
	agentId      string
	storeType    string
	schedule     string
	containerId  int
	password     string
	resourceName string
}

func TestAccKeyfactorCertificateStoreResource(t *testing.T) {

	containerId1, _ := strconv.Atoi(os.Getenv("KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1"))
	containerId2, _ := strconv.Atoi(os.Getenv("KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID2"))

	r := certificateStoreTestCase{
		orchestrator: os.Getenv("KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE"),
		storePath:    os.Getenv("KEYFACTOR_CERTIFICATE_STORE_PATH"),
		agentId:      os.Getenv("KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID"),
		storeType:    os.Getenv("KEYFACTOR_CERTIFICATE_STORE_TYPE"),
		containerId:  containerId1,
		password:     os.Getenv("KEYFACTOR_CERTIFICATE_STORE_PASS"),
		resourceName: "keyfactor_certificate_store.tf_acc_test",
	}

	// Update to multiple certificateStores test
	r2 := r
	r2.containerId = containerId2
	r2.schedule = "immediate"

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
			{
				Config: testAccKeyfactorCertificateStoreResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r2.resourceName, "store_path"),         // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "store_type"),         // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "client_machine"),     // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "agent_id"),           // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "inventory_schedule"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "container_id"),       // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "password"),           // TODO: Check specific value
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccKeyfactorCertificateStoreResourceConfig(t certificateStoreTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_certificate_store" "iis_trusted_roots" {
  client_machine = "%s" # Orchestrator client name
  store_path     = "%s" # Varies based on store type
  agent_id       = "%s" # Orchestrator GUID
  store_type     = "%s" # Must exist in KeyFactor
  properties = {
    # Optional properties based on the store type
    UseSSL = true
  }
  inventory_schedule = "%s" # How often to update the inventory
  container_id       = %v   # ID of the KeyFactor container
  password           = "%s"
  # The password for the certificate store. Note: This is bad practice, use TF_VAR_<variable_name> instead.
}
`, t.orchestrator, t.storePath, t.agentId, t.storeType, t.schedule, t.containerId, t.password)
	return output
}
