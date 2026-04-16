package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestIntKeyfactorCertificateStoreTypesDataSource verifies the
// keyfactor_certificate_store_types (plural) data source returns a list of
// store types and supports filtering.
func TestIntKeyfactorCertificateStoreTypesDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	// Test 1: No filters — should return at least one store type
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreTypesDataSourceConfigNoFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_store_types.test", "id"),
					resource.TestCheckResourceAttrWith("data.keyfactor_certificate_store_types.test", "store_types.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one store type, got 0")
						}
						return nil
					}),
				),
			},
		},
	})

	// Test 2: Filter by short_name substring — discover a known short name first
	allTypes, err := client.ListCertificateStoreTypes()
	if err != nil || allTypes == nil || len(*allTypes) == 0 {
		t.Log("Skipping short_name_filter sub-test: no store types available")
		return
	}

	firstType := (*allTypes)[0]
	shortName := firstType.ShortName

	if shortName != "" {
		// Use the first two characters as a substring filter
		prefix := shortName
		if len(prefix) > 3 {
			prefix = prefix[:3]
		}

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccCertStoreTypesDataSourceConfigShortNameFilter(prefix),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrWith("data.keyfactor_certificate_store_types.test", "store_types.#", func(value string) error {
							if value == "0" {
								return fmt.Errorf("expected at least one store type matching short_name prefix %q, got 0", prefix)
							}
							return nil
						}),
					),
				},
			},
		})
	}

	// Test 3: Filter by capability substring
	if firstType.Capability != "" {
		cap := firstType.Capability
		if len(cap) > 4 {
			cap = cap[:4]
		}

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccCertStoreTypesDataSourceConfigCapabilityFilter(cap),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrWith("data.keyfactor_certificate_store_types.test", "store_types.#", func(value string) error {
							if value == "0" {
								return fmt.Errorf("expected at least one store type with capability containing %q, got 0", cap)
							}
							return nil
						}),
					),
				},
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateStoreTypesDataSource tests the
// keyfactor_certificate_store_types (plural) data source using VCR cassettes.
func TestUnitKeyfactorCertificateStoreTypesDataSource(t *testing.T) {
	cassetteName := "certificate_store_types_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var params certStoreTypesDataSourceTestParams
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		types, err := client.ListCertificateStoreTypes()
		if err != nil || types == nil || len(*types) == 0 {
			t.Skip("No store types available for recording")
		}
		params = certStoreTypesDataSourceTestParams{
			StoreTypeCount:  len(*types),
			FirstShortName:  (*types)[0].ShortName,
			FirstCapability: (*types)[0].Capability,
		}
		writeCertStoreTypesDataSourceTestParams(cassettePath, params)
	} else {
		params = readCertStoreTypesDataSourceTestParams(cassettePath)
		if params.StoreTypeCount == 0 {
			t.Skip("No store type params recorded; skipping")
		}
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dsName := "data.keyfactor_certificate_store_types.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// No filter — all store types returned
				Config: testAccCertStoreTypesDataSourceConfigNoFilter(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttrWith(dsName, "store_types.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one store type, got 0")
						}
						return nil
					}),
					// First entry should have required fields populated
					resource.TestCheckResourceAttrSet(dsName, "store_types.0.short_name"),
					resource.TestCheckResourceAttrSet(dsName, "store_types.0.name"),
				),
			},
			{
				// Filter by exact short_name — should return exactly this store type
				Config: testAccCertStoreTypesDataSourceConfigShortNameFilter(params.FirstShortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dsName, "store_types.#", "1"),
					resource.TestCheckResourceAttr(dsName, "store_types.0.short_name", params.FirstShortName),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// HCL config generators
// ---------------------------------------------------------------------------

func testAccCertStoreTypesDataSourceConfigNoFilter() string {
	return `
data "keyfactor_certificate_store_types" "test" {}
`
}

func testAccCertStoreTypesDataSourceConfigShortNameFilter(prefix string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_store_types" "test" {
  short_name_filter = %q
}
`, prefix)
}

func testAccCertStoreTypesDataSourceConfigCapabilityFilter(cap string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_store_types" "test" {
  capability_filter = %q
}
`, cap)
}
