package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
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
