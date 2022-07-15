package keyfactor

import (
	"fmt"
	keyfactor "github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAccKeyfactorAttachRoleBasic(t *testing.T) {
	skipRole := testAccKeyfactorAttachRoleCheckSkip()
	if skipRole {
		t.Skip("Skipping attach role tests (KEYFACTOR_SKIP_ATTACH_ROLE_TESTS=true)")
	}

	template1, template2 := testAccCheckKeyfactorAttachRoleGetConfig(t)

	templateId1, err := strconv.Atoi(template1)
	if err != nil {
		t.Fatal(err)
	}
	templateId2, err := strconv.Atoi(template2)
	if err != nil {
		t.Fatal(err)
	}

	client, roleName, roleId := testAccGenerateKeyfactorRole(nil)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		IDRefreshName:     "keyfactor_attach_role.test",
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccKeyfactorAttachRoleDestroy,
		Steps: []resource.TestStep{
			// See if we can add a single template
			{
				Config: testAccKeyfactorAttachRoleBasic(roleName, templateId1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorAttachRoleRelationshipExists("keyfactor_attach_role.test", templateId1, 1),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.#", "1"),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.0", template1),
				),
			},
			// See if we can add a second template
			{
				Config: testAccKeyfactorAttachRoleBasicModified(roleName, templateId1, templateId2),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorAttachRoleRelationshipExists("keyfactor_attach_role.test", templateId1, 2),
					testAccCheckKeyfactorAttachRoleRelationshipExists("keyfactor_attach_role.test", templateId2, 2),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.#", "2"),
					resource.TestCheckResourceAttrSet("keyfactor_attach_role.test", "template_id_list.0"),
					resource.TestCheckResourceAttrSet("keyfactor_attach_role.test", "template_id_list.1"),
				),
			},
			// See what happens if we switch the order of the templates as they're configured
			{
				Config: testAccKeyfactorAttachRoleBasicModified(roleName, templateId2, templateId1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorAttachRoleRelationshipExists("keyfactor_attach_role.test", templateId2, 2),
					testAccCheckKeyfactorAttachRoleRelationshipExists("keyfactor_attach_role.test", templateId1, 2),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.#", "2"),
					resource.TestCheckResourceAttrSet("keyfactor_attach_role.test", "template_id_list.0"),
					resource.TestCheckResourceAttrSet("keyfactor_attach_role.test", "template_id_list.1"),
				),
			},
			// See what happens if we remove one of the templates
			{
				Config: testAccKeyfactorAttachRoleBasic(roleName, templateId1),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorAttachRoleRelationshipExists("keyfactor_attach_role.test", templateId1, 1),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.#", "1"),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.0", template1),
				),
			},
			// See what happens if we change the template
			{
				Config: testAccKeyfactorAttachRoleBasic(roleName, templateId2),
				Check: resource.ComposeTestCheckFunc(
					// Check inputted values
					testAccCheckKeyfactorAttachRoleRelationshipExists("keyfactor_attach_role.test", templateId2, 1),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "role_name", roleName),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.#", "1"),
					resource.TestCheckResourceAttr("keyfactor_attach_role.test", "template_id_list.0", template2),
				),
			},
		},
	})
	err = testAccDeleteKeyfactorRole(client, roleId)
	if err != nil {
		t.Fatal(err)
	}
}

func testAccCheckKeyfactorAttachRoleRelationshipExists(name string, templateId int, numberOfTemplates int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("no Identity ID set")
		}

		conn := testAccProvider.Meta().(*keyfactor.Client)
		roleName := rs.Primary.ID
		// conn is a configured Keyfactor Go Client object, get all template attachments
		err, attachments := findTemplateRoleAttachments(conn, roleName)
		if err != nil {
			return err
		}

		if len(attachments) != numberOfTemplates {
			return fmt.Errorf("expected role %s to be attached to %d templates, but is only attached to %d", roleName, numberOfTemplates, len(attachments))
		}

		for _, template := range attachments {
			// Relationship exists if the passed templateID matches one of the IDs returned by the find attachments function
			if template == templateId {
				return nil
			}
		}

		return fmt.Errorf("role %s is not assigned as allowed requestor for template with ID %d", roleName, templateId)
	}
}

func testAccCheckKeyfactorAttachRoleGetConfig(t *testing.T) (string, string) {
	var template1, template2 string
	if template1 = os.Getenv("KEYFACTOR_ATTACH_ROLE_TEMPLATE1"); template1 == "" {
		t.Log("Note: Terraform Attach Role tests attempt to add a security identity as an allowed requestor on a template.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_ATTACH_ROLE_TESTS to 'true' to skip Security Identity " +
			"resource acceptance tests")
		t.Fatal("KEYFACTOR_ATTACH_ROLE_TEMPLATE1 must be set to perform Attach Role acceptance test. " +
			"(EX '14'")
	}
	if template2 = os.Getenv("KEYFACTOR_ATTACH_ROLE_TEMPLATE2"); template2 == "" {
		t.Log("Note: Terraform Attach Role tests attempt to add a security identity as an allowed requester on a template.")
		t.Log("Set an environment variable for KEYFACTOR_SKIP_ATTACH_ROLE_TESTS to 'true' to skip Security Identity " +
			"resource acceptance tests")
		t.Fatal("KEYFACTOR_ATTACH_ROLE_TEMPLATE2 must be set to perform Attach Role acceptance test. " +
			"(EX '14'")
	}
	return template1, template2
}

func testAccKeyfactorAttachRoleCheckSkip() bool {
	skipAttachRoleTests := false
	if temp := os.Getenv("KEYFACTOR_SKIP_ATTACH_ROLE_TESTS"); temp != "" {
		if strings.ToLower(temp) == "true" {
			skipAttachRoleTests = true
		}
	}
	return skipAttachRoleTests
}

func testAccKeyfactorAttachRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "keyfactor_attach_role" {
			continue
		}

		roleName := rs.Primary.ID

		// Pull the provider metadata interface out of the testAccProvider provider
		conn := testAccProvider.Meta().(*keyfactor.Client)

		// conn is a configured Keyfactor Go Client object, get all template attachments
		err, attachments := findTemplateRoleAttachments(conn, roleName)
		if err != nil {
			return err
		}

		if len(attachments) > 0 {
			return fmt.Errorf("resource still exists, found role attached to %d templates", len(attachments))
		}

		// If we get here, the relationship doesn't exist in Keyfactor
	}
	return nil
}

func testAccKeyfactorAttachRoleBasic(roleName string, templateId int) string {
	return fmt.Sprintf(`
	resource "keyfactor_attach_role" "test" {
		role_name = "%s"
		template_id_list = [%d]
	}
	`, roleName, templateId)
}

func testAccKeyfactorAttachRoleBasicModified(roleName string, templateId1 int, templateId2 int) string {
	return fmt.Sprintf(`
	resource "keyfactor_attach_role" "test" {
		role_name = "%s"
		template_id_list = [%d, %d]
	}
	`, roleName, templateId1, templateId2)
}
