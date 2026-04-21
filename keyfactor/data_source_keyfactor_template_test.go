package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// TestIntKeyfactorCertificateTemplateDataSourceLegacy provides int-test
// coverage for the legacy TestAcc pattern in this file.
func TestIntKeyfactorCertificateTemplateDataSourceLegacy(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}
	templates, err := client.GetTemplates()
	if err != nil || len(templates) == 0 {
		t.Skip("Skipping: no certificate templates found in lab")
	}
	tmplName := templates[0].CommonName

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "keyfactor_certificate_template" "test" {
  identifier = "%s"
}
`, tmplName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_template.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate_template.test", "common_name", tmplName),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_template.test", "template_name"),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateTemplateDataSourceLegacy provides VCR unit-test
// coverage for this legacy file. The cassette is shared with
// TestUnitKeyfactorCertificateTemplateDataSource in
// data_source_keyfactor_certificate_template_test.go.
func TestUnitKeyfactorCertificateTemplateDataSourceLegacy(t *testing.T) {
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
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dsName := "data.keyfactor_certificate_template.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "keyfactor_certificate_template" "test" {
  identifier = "%s"
}
`, tmplName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "common_name", tmplName),
					resource.TestCheckResourceAttrSet(dsName, "template_name"),
				),
			},
		},
	})
}

func TestAccKeyfactorCertificateTemplateDataSource(t *testing.T) {
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_certificate_template")
	var templateName = os.Getenv("KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1")
	if templateName == "" {
		t.Skip("Skipping: KEYFACTOR_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1 not set")
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "keyfactor_certificate_template" "test" {
  identifier = "%s"
}
`, templateName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "common_name", templateName),
					resource.TestCheckResourceAttrSet(resourceName, "template_name"),
					resource.TestCheckResourceAttrSet(resourceName, "oid"),
					resource.TestCheckResourceAttrSet(resourceName, "key_size"),
					resource.TestCheckResourceAttrSet(resourceName, "key_type"),
					resource.TestCheckResourceAttrSet(resourceName, "forest_root"),
					resource.TestCheckResourceAttrSet(resourceName, "key_retention"),
					resource.TestCheckResourceAttrSet(resourceName, "key_retention_days"),
					resource.TestCheckResourceAttrSet(resourceName, "key_archival"),
					resource.TestCheckResourceAttrSet(resourceName, "allowed_enrollment_types"),
					resource.TestCheckResourceAttrSet(resourceName, "requires_approval"),
					resource.TestCheckResourceAttrSet(resourceName, "key_usage"),
				),
			},
		},
	})
}
