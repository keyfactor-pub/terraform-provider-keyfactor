package keyfactor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type roleBindingTestCase struct {
	roleName     string
	templates    []string
	templatesStr string
	resourceName string
}

func TestAccKeyfactorTemplateRoleBindingResource(t *testing.T) {

	r := roleBindingTestCase{
		roleName: os.Getenv("KEYFACTOR_TEMPLATE_ROLE_BINDING_ROLE_NAME"),
		templates: []string{
			os.Getenv("KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1"),
		},
		resourceName: "keyfactor_template_role_binding.terraform_test",
	}
	pStr, _ := json.Marshal(r.templates)
	r.templatesStr = string(pStr)

	// Update to multiple roleBindings test
	r2 := r
	additionalTemplates := []string{
		os.Getenv("KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME2"),
		os.Getenv("KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME3"),
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

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorTemplateRoleBindingResource exercises the template role
// binding resource. Because the keyfactor-go-client UpdateTemplateArg struct
// is missing the Policies field required by Command v25+, the apply step is
// expected to fail with an error.  The cassette captures the role Create and
// the attempted template update that yields the server error.
func TestUnitKeyfactorTemplateRoleBindingResource(t *testing.T) {
	cassetteName := "template_role_binding_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var roleName, templateName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		enrollmentPattern := discoverEnrollmentPattern(t, client)
		if enrollmentPattern == "" {
			t.Skip("Template role binding requires enrollment patterns (Command v25+)")
		}
		templateName = discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
		if templateName == "" {
			templateName = discoverTemplate(t, client)
		}
		roleName = fmt.Sprintf("tf-unit-binding-%d", time.Now().UnixNano())
		writeRoleBindingTestParams(cassettePath, roleBindingTestParams{RoleName: roleName, TemplateName: templateName})
	} else {
		params := readRoleBindingTestParams(cassettePath)
		if params.RoleName == "" {
			t.Skip("No template role binding cassette recorded. Run with RECORD_CASSETTES=1 against a v25+ lab.")
		}
		roleName = params.RoleName
		templateName = params.TemplateName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "unit_binding_test" {
  name        = %q
  description = "Unit test role for binding"
  permissions = []
}

resource "keyfactor_template_role_binding" "unit_test" {
  role_name            = keyfactor_role.unit_binding_test.name
  template_short_names = [%q]
}
`, roleName, templateName),
				ExpectError: regexp.MustCompile(`(?i)Policies.*cannot be empty|Error updating template`),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorTemplateRoleBindingResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	// Template must be associated with an enrollment pattern for binding to work.
	// If no enrollment patterns are available, skip this test.
	enrollmentPattern := discoverEnrollmentPattern(t, client)
	if enrollmentPattern == "" {
		t.Skip("Template role binding requires templates with enrollment patterns (Command v25+)")
	}

	// Use the template from the enrollment pattern — it's guaranteed to be linked
	templateName := discoverEnrollmentPatternTemplate(t, client, enrollmentPattern)
	if templateName == "" {
		templateName = discoverTemplate(t, client)
	}
	roleName := fmt.Sprintf("tf-int-test-binding-%d", time.Now().UnixNano())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Known limitation: the keyfactor-go-client v3 UpdateTemplateArg struct
				// doesn't include a Policies field required by Command v25+.
				// This test validates the expected error until the client library is updated.
				Config: fmt.Sprintf(`
resource "keyfactor_role" "int_binding_test" {
	name        = "%s"
	description = "Integration test role for binding"
	permissions = []
}

resource "keyfactor_template_role_binding" "int_test" {
	role_name            = keyfactor_role.int_binding_test.name
	template_short_names = ["%s"]
}
`, roleName, templateName),
				ExpectError: regexp.MustCompile(`(?i)Policies.*cannot be empty|Error updating template`),
			},
		},
	})
}
