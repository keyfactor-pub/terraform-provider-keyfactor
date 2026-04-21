package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// TestAcc — full lifecycle (legacy, requires many env vars)
// ---------------------------------------------------------------------------

func TestAccKeyfactorCertificateStoreTypeResource(t *testing.T) {
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
	shortName := fmt.Sprintf("TF%06d", time.Now().UnixNano()%1000000)
	baseName := os.Getenv("KEYFACTOR_CERT_STORE_TYPE_NAME")
	if baseName == "" {
		baseName = "tf-acc-store-type"
	}
	name := fmt.Sprintf("%s-%d", baseName, time.Now().UnixNano()%1000000000)
	resourceName := "keyfactor_certificate_store_type.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create
			{
				Config: testAccCertStoreTypeConfig(name, shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
					resource.TestCheckResourceAttrSet(resourceName, "supports_add"),
					resource.TestCheckResourceAttrSet(resourceName, "private_key_allowed"),
				),
			},
			// Update name (short_name cannot change — would force replace)
			{
				Config: testAccCertStoreTypeConfig(name+"-updated", shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
				),
			},
			// Import by short_name
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     shortName,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccKeyfactorCertificateStoreTypeResourceWithProperties(t *testing.T) {
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
	shortName := fmt.Sprintf("TFP%05d", time.Now().UnixNano()%100000)
	name := fmt.Sprintf("tf-acc-store-type-props-%d", time.Now().UnixNano()%1000000000)
	resourceName := "keyfactor_certificate_store_type.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreTypeConfigWithProperties(name, shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
					resource.TestCheckResourceAttr(resourceName, "properties.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "properties.0.name", "Host"),
					resource.TestCheckResourceAttr(resourceName, "properties.0.type", "String"),
					resource.TestCheckResourceAttr(resourceName, "properties.0.required", "true"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// TestInt — auto-discovery, only need connection env vars
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateStoreTypeResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	shortName := fmt.Sprintf("TF%06d", time.Now().UnixNano()%1000000)
	name := randomTestCN("tf-int-store-type")
	resourceName := "keyfactor_certificate_store_type.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create
			{
				Config: testAccCertStoreTypeConfig(name, shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
					resource.TestCheckResourceAttrSet(resourceName, "supports_add"),
					resource.TestCheckResourceAttrSet(resourceName, "private_key_allowed"),
					resource.TestCheckResourceAttrSet(resourceName, "custom_alias_allowed"),
				),
			},
			// Update name
			{
				Config: testAccCertStoreTypeConfig(name+"-v2", shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name+"-v2"),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
				),
			},
			// Import by short_name
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     shortName,
				ImportStateVerify: true,
			},
		},
	})
}

func TestIntKeyfactorCertificateStoreTypeResourceWithProperties(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	shortName := fmt.Sprintf("TFP%05d", time.Now().UnixNano()%100000)
	name := randomTestCN("tf-int-store-type-props")
	resourceName := "keyfactor_certificate_store_type.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreTypeConfigWithProperties(name, shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
					resource.TestCheckResourceAttr(resourceName, "properties.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "properties.0.name", "Host"),
					resource.TestCheckResourceAttr(resourceName, "properties.0.type", "String"),
					resource.TestCheckResourceAttr(resourceName, "properties.0.required", "true"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Data source integration tests
// ---------------------------------------------------------------------------

func TestIntKeyfactorCertificateStoreTypeDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	shortName := fmt.Sprintf("TFDS%05d", time.Now().UnixNano()%100000)
	name := randomTestCN("tf-int-store-type-ds")
	resourceName := "keyfactor_certificate_store_type.test"
	dsName := "data.keyfactor_certificate_store_type.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create and read back via data source by short_name
				Config: testAccCertStoreTypeConfig(name, shortName) + "\n" +
					testAccCertStoreTypeDataSourceByShortName(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "name", name),
					resource.TestCheckResourceAttr(dsName, "short_name", shortName),
				),
			},
			{
				// Read back by numeric ID
				Config: testAccCertStoreTypeConfig(name, shortName) + "\n" +
					testAccCertStoreTypeDataSourceByID(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "name", name),
					resource.TestCheckResourceAttr(dsName, "short_name", shortName),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorCertificateStoreTypeResource tests the certificate store type
// resource create/update lifecycle using VCR cassettes.
func TestUnitKeyfactorCertificateStoreTypeResource(t *testing.T) {
	cassetteName := "certificate_store_type_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var name, shortName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		ts := time.Now().UnixNano() % 1000000000
		name = fmt.Sprintf("tf-unit-store-type-%d", ts)
		shortName = fmt.Sprintf("TFU%d", ts%1000000)
		writeCertStoreTypeTestParams(cassettePath, certStoreTypeTestParams{Name: name, ShortName: shortName})
	} else {
		params := readCertStoreTypeTestParams(cassettePath)
		name = params.Name
		shortName = params.ShortName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store_type.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertStoreTypeConfig(name, shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
					resource.TestCheckResourceAttr(resourceName, "supports_add", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_remove", "true"),
					resource.TestCheckResourceAttr(resourceName, "private_key_allowed", "Optional"),
					resource.TestCheckResourceAttr(resourceName, "custom_alias_allowed", "Forbidden"),
					resource.TestCheckResourceAttr(resourceName, "server_required", "false"),
				),
			},
			{
				Config: testAccCertStoreTypeConfig(name+"-v2", shortName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name+"-v2"),
					resource.TestCheckResourceAttr(resourceName, "short_name", shortName),
				),
			},
		},
	})
}

// TestUnitKeyfactorCertificateStoreTypeDataSource tests the single
// keyfactor_certificate_store_type data source using VCR cassettes.
func TestUnitKeyfactorCertificateStoreTypeDataSource(t *testing.T) {
	cassetteName := "certificate_store_type_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var name, shortName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		ts := time.Now().UnixNano() % 1000000000
		name = fmt.Sprintf("tf-unit-store-type-ds-%d", ts)
		shortName = fmt.Sprintf("TFUDS%d", ts%100000)
		writeCertStoreTypeTestParams(cassettePath, certStoreTypeTestParams{Name: name, ShortName: shortName})
	} else {
		params := readCertStoreTypeTestParams(cassettePath)
		name = params.Name
		shortName = params.ShortName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_certificate_store_type.test"
	dsName := "data.keyfactor_certificate_store_type.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Create and read back by short_name
				Config: testAccCertStoreTypeConfig(name, shortName) + "\n" +
					testAccCertStoreTypeDataSourceByShortName(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "name", name),
					resource.TestCheckResourceAttr(dsName, "short_name", shortName),
					resource.TestCheckResourceAttr(dsName, "supports_add", "true"),
				),
			},
			{
				// Read back by numeric ID
				Config: testAccCertStoreTypeConfig(name, shortName) + "\n" +
					testAccCertStoreTypeDataSourceByID(resourceName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "name", name),
					resource.TestCheckResourceAttr(dsName, "short_name", shortName),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccCertStoreTypeConfig(name, shortName string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_store_type" "test" {
  name       = %q
  short_name = %q

  supports_add    = true
  supports_remove = true

  private_key_allowed  = "Optional"
  custom_alias_allowed = "Forbidden"
  server_required      = false
}
`, name, shortName)
}

func testAccCertStoreTypeConfigWithProperties(name, shortName string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_store_type" "test" {
  name       = %q
  short_name = %q

  supports_add    = true
  supports_remove = true

  private_key_allowed  = "Optional"
  custom_alias_allowed = "Forbidden"
  server_required      = false

  properties = [
    {
      name         = "Host"
      display_name = "Target Host"
      type         = "String"
      required     = true
    },
  ]
}
`, name, shortName)
}

func testAccCertStoreTypeDataSourceByShortName(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_store_type" "test" {
  identifier = %s.short_name
}
`, resourceRef)
}

func testAccCertStoreTypeDataSourceByID(resourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_store_type" "test" {
  identifier = %s.id
}
`, resourceRef)
}
