package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Integration tests
//
// Templates cannot be created via API — they are imported from the CA.
// These tests discover an existing template and exercise import + update.
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateTemplateResourceImport(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	templates, err := client.GetTemplates()
	if err != nil || len(templates) == 0 {
		t.Skip("Skipping: no certificate templates found in lab")
	}
	tmpl := templates[0]
	tmplID := strconv.Itoa(tmpl.Id)
	tmplName := tmpl.CommonName

	t.Logf("Using template: ID=%s CommonName=%q", tmplID, tmplName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             nil, // delete is a no-op
		Steps: []resource.TestStep{
			{
				// Import existing template by ID
				Config:            testAccCertificateTemplateImportConfig(),
				ResourceName:      "keyfactor_certificate_template.test",
				ImportState:       true,
				ImportStateId:     tmplID,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keyfactor_certificate_template.test", "id", tmplID),
					resource.TestCheckResourceAttr("keyfactor_certificate_template.test", "common_name", tmplName),
					resource.TestCheckResourceAttrSet("keyfactor_certificate_template.test", "template_name"),
				),
			},
		},
	})
}

// TestIntKeyfactorCertificateTemplateResourceUpdate imports a template and
// then applies a config change, verifying the update is reflected in state.
func TestIntKeyfactorCertificateTemplateResourceUpdate(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	templates, err := client.GetTemplates()
	if err != nil || len(templates) == 0 {
		t.Skip("Skipping: no certificate templates found in lab")
	}

	// Pick the first template
	tmpl := templates[0]
	tmplID := strconv.Itoa(tmpl.Id)
	tmplName := tmpl.CommonName
	t.Logf("Using template: ID=%s CommonName=%q", tmplID, tmplName)

	resourceName := "keyfactor_certificate_template.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             nil, // delete is a no-op
		Steps: []resource.TestStep{
			{
				// Step 1: import
				Config:            testAccCertificateTemplateImportConfig(),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     tmplID,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", tmplID),
					resource.TestCheckResourceAttr(resourceName, "common_name", tmplName),
				),
			},
			{
				// Step 2: update — set allowed_enrollment_types and requires_approval
				Config: testAccCertificateTemplateUpdateConfig(false, 3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", tmplID),
					resource.TestCheckResourceAttr(resourceName, "common_name", tmplName),
					resource.TestCheckResourceAttr(resourceName, "requires_approval", "false"),
					resource.TestCheckResourceAttr(resourceName, "allowed_enrollment_types", "3"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

func TestUnitKeyfactorCertificateTemplateResource(t *testing.T) {
	cassetteName := "certificate_template_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var tmplID, tmplName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		if client == nil {
			t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
		}
		templates, err := client.GetTemplates()
		if err != nil || len(templates) == 0 {
			t.Skip("Skipping: no certificate templates found in lab")
		}
		tmplID = strconv.Itoa(templates[0].Id)
		tmplName = templates[0].CommonName
		writeTemplateTestParams(cassettePath, templateTestParams{TemplateID: tmplID, TemplateName: tmplName})
	} else {
		params := readTemplateTestParams(cassettePath)
		tmplID = params.TemplateID
		tmplName = params.TemplateName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_template.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		CheckDestroy:             nil,
		Steps: []resource.TestStep{
			{
				Config:            testAccCertificateTemplateImportConfig(),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     tmplID,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", tmplID),
					resource.TestCheckResourceAttr(resourceName, "common_name", tmplName),
					resource.TestCheckResourceAttrSet(resourceName, "template_name"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateTemplateResource_Update tests the import→update
// flow using VCR cassettes.
//
// To record cassettes:
//
//	RECORD_CASSETTES=1 make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateTemplateResource_Update
func TestUnitKeyfactorCertificateTemplateResource_Update(t *testing.T) {
	cassetteName := "certificate_template_resource_update"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var tmplID, tmplName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		if client == nil {
			t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
		}
		templates, err := client.GetTemplates()
		if err != nil || len(templates) == 0 {
			t.Skip("Skipping: no certificate templates found in lab")
		}
		tmplID = strconv.Itoa(templates[0].Id)
		tmplName = templates[0].CommonName
		writeTemplateTestParams(cassettePath, templateTestParams{TemplateID: tmplID, TemplateName: tmplName})
	} else {
		params := readTemplateTestParams(cassettePath)
		tmplID = params.TemplateID
		tmplName = params.TemplateName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_template.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		CheckDestroy:             nil,
		Steps: []resource.TestStep{
			{
				// Step 1: import
				Config:            testAccCertificateTemplateImportConfig(),
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     tmplID,
				ImportStateVerify: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", tmplID),
					resource.TestCheckResourceAttr(resourceName, "common_name", tmplName),
					resource.TestCheckResourceAttrSet(resourceName, "template_name"),
				),
			},
			{
				// Step 2: apply update
				Config: testAccCertificateTemplateUpdateConfig(false, 3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "requires_approval", "false"),
					resource.TestCheckResourceAttr(resourceName, "allowed_enrollment_types", "3"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccCertificateTemplateImportConfig() string {
	return `
resource "keyfactor_certificate_template" "test" {
}
`
}

// testAccCertificateTemplateUpdateConfig generates a config that sets
// requires_approval and allowed_enrollment_types on the template.
func testAccCertificateTemplateUpdateConfig(requiresApproval bool, enrollmentTypes int) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_template" "test" {
  requires_approval        = %t
  allowed_enrollment_types = %d
}
`, requiresApproval, enrollmentTypes)
}
