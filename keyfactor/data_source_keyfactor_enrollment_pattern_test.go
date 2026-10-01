package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorEnrollmentPatternDataSource tests the
// keyfactor_enrollment_pattern data source using VCR cassettes.
// Note: enrollment patterns require Command v25+. The cassette for this test
// must be recorded against a v25+ lab. If no cassette exists, the test skips.
func TestUnitKeyfactorEnrollmentPatternDataSource(t *testing.T) {
	cassetteName := "enrollment_pattern_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var patternName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		patternName = discoverEnrollmentPattern(t, client)
		if patternName == "" {
			t.Skip("No enrollment patterns available (requires Command v25+)")
		}
		writeEnrollmentPatternTestParams(cassettePath, enrollmentPatternTestParams{
			PatternName: patternName,
		})
	} else {
		params := readEnrollmentPatternTestParams(cassettePath)
		patternName = params.PatternName
		if patternName == "" {
			t.Skip("No enrollment pattern cassette recorded (requires Command v25+); record with: make testunit-record-enrollment-pattern")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccEnrollmentPatternDataSourceConfig(patternName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_enrollment_pattern.test", "name", patternName),
					resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "allowed_enrollment_types"),
					resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "template_default"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorEnrollmentPatternDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	patternName := discoverEnrollmentPattern(t, client)
	if patternName == "" {
		t.Skip("No enrollment patterns available (requires Command v25+)")
	}

	// Test 1: Look up by name
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEnrollmentPatternDataSourceConfig(patternName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_enrollment_pattern.test", "name", patternName),
					resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "allowed_enrollment_types"),
					resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "template_default"),
				),
			},
		},
	})

	// Test 2: Look up by numeric ID (discover ID first via API)
	patterns, err := client.GetEnrollmentPatterns()
	if err != nil {
		t.Fatalf("Failed to get enrollment patterns for ID lookup test: %s", err)
	}
	for _, p := range patterns {
		if p.Name == patternName {
			idStr := fmt.Sprintf("%d", p.ID)
			t.Logf("Testing enrollment pattern lookup by ID: %s", idStr)
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: testAccEnrollmentPatternDataSourceConfig(idStr),
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "id"),
							resource.TestCheckResourceAttr("data.keyfactor_enrollment_pattern.test", "name", patternName),
						),
					},
				},
			})
			break
		}
	}
}

// TestIntKeyfactorEnrollmentPatternDataSource_TemplateShortName tests the
// template_short_name lookup path of the keyfactor_enrollment_pattern data
// source. It discovers the template short name (AD common name) associated
// with the default enrollment pattern and queries for it, verifying that the
// server-side QueryString filter resolves to the correct pattern.
func TestIntKeyfactorEnrollmentPatternDataSource_TemplateShortName(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	patternName := discoverEnrollmentPattern(t, client)
	if patternName == "" {
		t.Skip("No enrollment patterns available (requires Command v25+)")
	}

	templateShortName := discoverEnrollmentPatternTemplate(t, client, patternName)
	if templateShortName == "" {
		t.Skip("Could not discover template short name for the enrollment pattern; skipping template_short_name lookup test")
	}
	t.Logf("Testing enrollment pattern lookup by template_short_name: %q (from pattern %q)", templateShortName, patternName)

	// Independent subtests so a failure in one does not prevent the other
	// from running. Each wraps its own resource.Test call.

	// Subtest 1: lookup with template_default = true.
	// discoverEnrollmentPattern prefers TemplateDefault patterns, so the
	// discovered pattern is guaranteed to be the default for its template.
	// This path resolves deterministically regardless of how many patterns
	// share the template.
	t.Run("with template_default=true", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccEnrollmentPatternDataSourceConfigByTemplateShortName(templateShortName, true),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "id"),
						resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "name"),
						resource.TestCheckResourceAttr("data.keyfactor_enrollment_pattern.test", "template_default", "true"),
						resource.TestCheckResourceAttr("data.keyfactor_enrollment_pattern.test", "template_short_name", templateShortName),
						resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "template.common_name"),
					),
				},
			},
		})
	})

	// Subtest 2: lookup without template_default filter.
	// This only passes when the lab has exactly one enrollment pattern for
	// the template. If the lab has multiple, the provider returns an
	// "ambiguous" error and this subtest fails — but subtest 1 will have
	// already verified the core lookup path, so a failure here signals a
	// lab-config edge case rather than a code regression.
	t.Run("without template_default filter", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccEnrollmentPatternDataSourceConfigByTemplateShortName(templateShortName, false),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "id"),
						resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "name"),
						resource.TestCheckResourceAttrSet("data.keyfactor_enrollment_pattern.test", "template_default"),
					),
				},
			},
		})
	})

	// Subtest 3: error path — nonsense template_short_name that matches no
	// enrollment pattern. The provider must return a "no enrollment pattern
	// found" error rather than silently producing an empty/zero result.
	t.Run("no match returns error", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config:      testAccEnrollmentPatternDataSourceConfigByTemplateShortName("__nonexistent_template_xyz__", false),
					ExpectError: regexp.MustCompile(`(?i)no enrollment pattern found`),
				},
			},
		})
	})
}
