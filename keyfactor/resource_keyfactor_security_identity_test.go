package keyfactor

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

type identityTestCase struct {
	accountName  string
	roles        []string
	resourceName string
	rolesStr     string
}

func TestAccKeyfactorIdentityResource(t *testing.T) {
	// Single role test
	i := identityTestCase{
		accountName: `COMMAND\\terraformer`,
		roles: []string{
			"EnrollPFX",
		},
		resourceName: "keyfactor_identity.terraformer",
	}

	rStr, _ := json.Marshal(i.roles)
	i.rolesStr = string(rStr)

	// Update to multiple roles test
	i2 := i
	i2.roles = append(i2.roles, "Terraformer")
	r2Str, _ := json.Marshal(i2.roles)
	i2.rolesStr = string(r2Str)

	// Update to no roles test
	i3 := i2
	i3.roles = []string{}
	r3Str, _ := json.Marshal(i3.roles)
	i3.rolesStr = string(r3Str)

	// Testing Identity
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorIdentityResourceConfig(i),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(i.resourceName, "id"),
					resource.TestCheckResourceAttrSet(i.resourceName, "account_name"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(i.resourceName, "roles.0"),      // TODO: Check specific value

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
				Config: testAccKeyfactorIdentityResourceConfig(i2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(i2.resourceName, "id"),
					resource.TestCheckResourceAttrSet(i2.resourceName, "account_name"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(i2.resourceName, "roles.0"),      // TODO: Check specific value
					resource.TestCheckResourceAttrSet(i2.resourceName, "roles.1"),      // TODO: Check specific value
				),
			},
			{
				Config: testAccKeyfactorIdentityResourceConfig(i3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(i3.resourceName, "id"),
					resource.TestCheckResourceAttrSet(i3.resourceName, "account_name"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(i3.resourceName, "roles.#"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccKeyfactorIdentityResourceConfig(t identityTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_identity" "terraformer" {
	account_name = "%s"
	roles        = %s
}
`, t.accountName, t.rolesStr)
	return output
}
