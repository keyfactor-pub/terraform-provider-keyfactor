package keyfactor

import (
	"fmt"
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
// Config generators
// ---------------------------------------------------------------------------

func testAccCertificateTemplateDataSourceConfig(identifier string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_template" "test" {
  identifier = "%s"
}
`, identifier)
}
