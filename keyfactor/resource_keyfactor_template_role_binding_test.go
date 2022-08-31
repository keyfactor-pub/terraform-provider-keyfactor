package keyfactor

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

type roleBindingTestCase struct {
	roleName     string
	templates    []string
	templatesStr string
	resourceName string
}

func TestAccKeyfactorTemplateRoleBindingResource(t *testing.T) {

	r := roleBindingTestCase{
		roleName: "Terraform",
		templates: []string{
			"2YearTestWebServer",
		},
		resourceName: "keyfactor_template_role_binding.terraform_test",
	}
	pStr, _ := json.Marshal(r.templates)
	r.templatesStr = string(pStr)

	// Update to multiple roleBindings test
	r2 := r
	additionalTemplates := []string{
		"Workstation",
		"User",
	}
	r2.templates = append(r2.templates, additionalTemplates...)
	r2Str, _ := json.Marshal(r2.templates)
	r2.templatesStr = string(r2Str)

	// Update to no roleBindings test
	r3 := r2
	r3.templates = []string{}
	r3Str, _ := json.Marshal(r3.templates)
	r3.templatesStr = string(r3Str)

	// Testing Role
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorTemplateRoleBindingResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "role_name"),              // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "template_short_names.0"), // TODO: Check specific value

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
				Config: testAccKeyfactorTemplateRoleBindingResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r2.resourceName, "role_name"),              // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "template_short_names.0"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "template_short_names.1"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "template_short_names.2"), // TODO: Check specific value
				),
			},
			{
				Config: testAccKeyfactorTemplateRoleBindingResourceConfig(r3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r3.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r3.resourceName, "role_name"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r3.resourceName, "template_short_names.#"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccKeyfactorTemplateRoleBindingResourceConfig(t roleBindingTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_template_role_binding" "terraform_test" {
  role_name            = "%s" 
  template_short_names = %s 
}
`, t.roleName, t.templatesStr)
	return output
}
