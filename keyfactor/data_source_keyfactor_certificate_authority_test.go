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

func TestIntKeyfactorCertificateAuthorityDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	// Discover existing CA
	cas, err := client.GetCAList()
	if err != nil || len(cas) == 0 {
		t.Skip("Skipping: no certificate authority found in lab")
	}
	ca := cas[0]
	caName := ca.LogicalName

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Look up existing CA by name
				Config: testAccCertificateAuthorityDataSourceConfig(caName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_authority.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate_authority.test", "logical_name", caName),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_authority.test", "host_name"),
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_authority.test", "ca_type"),
				),
			},
		},
	})
}

func TestIntKeyfactorCertificateAuthorityDataSourceByID(t *testing.T) {
	client := testAccIntegrationPreCheck(t)
	if client == nil {
		t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
	}

	// Discover existing CA
	cas, err := client.GetCAList()
	if err != nil || len(cas) == 0 {
		t.Skip("Skipping: no certificate authority found in lab")
	}
	ca := cas[0]
	caID := strconv.Itoa(ca.Id)
	caName := ca.LogicalName

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Look up existing CA by integer ID
				Config: testAccCertificateAuthorityDataSourceConfig(caID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_certificate_authority.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_certificate_authority.test", "logical_name", caName),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

func TestUnitKeyfactorCertificateAuthorityDataSource(t *testing.T) {
	cassetteName := "certificate_authority_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var caName, caID string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := testAccIntegrationPreCheck(t)
		if client == nil {
			t.Skip("Skipping: testAccIntegrationPreCheck returned nil client")
		}
		cas, err := client.GetCAList()
		if err != nil || len(cas) == 0 {
			t.Skip("Skipping: no certificate authority found in lab")
		}
		caName = cas[0].LogicalName
		caID = strconv.Itoa(cas[0].Id)
		writeCATestParams(cassettePath, caTestParams{CAName: caName, CAID: caID, CAHost: cas[0].HostName})
	} else {
		params := readCATestParams(cassettePath)
		caName = params.CAName
		caID = params.CAID
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dsName := "data.keyfactor_certificate_authority.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Look up by name
				Config: testAccCertificateAuthorityDataSourceConfig(caName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "logical_name", caName),
					resource.TestCheckResourceAttrSet(dsName, "host_name"),
					resource.TestCheckResourceAttrSet(dsName, "ca_type"),
				),
			},
			{
				// Look up by ID
				Config: testAccCertificateAuthorityDataSourceConfig(caID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsName, "id"),
					resource.TestCheckResourceAttr(dsName, "logical_name", caName),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

func testAccCertificateAuthorityDataSourceConfig(identifier string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_authority" "test" {
  identifier = "%s"
}
`, identifier)
}
