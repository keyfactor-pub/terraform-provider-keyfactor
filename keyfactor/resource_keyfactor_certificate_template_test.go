package keyfactor

import (
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
// These tests discover an existing template and exercise import.
//
// Note: multi-step import→update testing is not possible with the Terraform
// plugin SDK testing framework when Create intentionally returns an error.
// The Update function is tested via TestIntKeyfactorCertificateTemplateResourceUpdateDirect.
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

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccCertificateTemplateImportConfig() string {
	return `
resource "keyfactor_certificate_template" "test" {
}
`
}
