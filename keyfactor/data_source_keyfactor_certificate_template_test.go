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
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateTemplateDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	templates, err := client.GetTemplates()
	if err != nil || len(templates) == 0 {
		t.Skip("Skipping: no certificate templates found in lab")
	}
	tmpl := templates[0]
	tmplName := tmpl.CommonName

	t.Logf("Using template: ID=%d CommonName=%q", tmpl.Id, tmplName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateTemplateDataSourceConfig(tmplName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_template.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate_template.test", "common_name", tmplName),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_template.test", "template_name"),
				),
			},
		},
	})
}

func TestIntKeyfactorCertificateTemplateDataSourceByID(t *testing.T) {
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
		Steps: []resource.TestStep{
			{
				Config: testAccCertificateTemplateDataSourceConfig(tmplID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_template.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate_template.test", "common_name", tmplName),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

func TestUnitKeyfactorCertificateTemplateDataSource(t *testing.T) {
	cassetteName := "certificate_template_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var tmplName, tmplID string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		if client == nil {
			t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
		}
		templates, err := client.GetTemplates()
		if err != nil || len(templates) == 0 {
			t.Skip("Skipping: no certificate templates found in lab")
		}
		tmplName = templates[0].CommonName
		tmplID = strconv.Itoa(templates[0].Id)
		writeTemplateTestParams(cassettePath, templateTestParams{TemplateName: tmplName, TemplateID: tmplID})
	} else {
		params := readTemplateTestParams(cassettePath)
		tmplName = params.TemplateName
		tmplID = params.TemplateID
	}

	factories, cleanup := newVCRProviderFactoriesReplayable(t, cassetteName)
	defer cleanup()

	dsName := "data.keyfactor_certificate_template.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Look up by name
				Config: testAccCertificateTemplateDataSourceConfig(tmplName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "common_name", tmplName),
					resource.TestCheckResourceAttrSet(dsName, "template_name"),
				),
			},
			{
				// Look up by ID
				Config: testAccCertificateTemplateDataSourceConfig(tmplID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "common_name", tmplName),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccCertificateTemplateDataSourceConfig(identifier string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_template" "test" {
  identifier = "%s"
}
`, identifier)
}
