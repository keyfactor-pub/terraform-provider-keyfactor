package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorSecurityIdentityDataSource(t *testing.T) {
	var resourceName = fmt.Sprintf("data.%s.test", "keyfactor_identity")
	var iNameEscaped = fmt.Sprintf("%s\\\\%s", strings.ToUpper(os.Getenv("KEYFACTOR_DOMAIN")), os.Getenv("KEYFACTOR_USERNAME"))
	var iName = fmt.Sprintf("%s\\%s", strings.ToUpper(os.Getenv("KEYFACTOR_DOMAIN")), os.Getenv("KEYFACTOR_USERNAME"))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccKeyfactorDataSourceSecurityIdentityBasic(iNameEscaped),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "account_name", iName),
					resource.TestCheckResourceAttrSet(resourceName, "roles.#"),
					resource.TestCheckResourceAttrSet(resourceName, "identity_type"),
					resource.TestCheckResourceAttrSet(resourceName, "valid"),
				),
			},
		},
	})
}

func testAccKeyfactorDataSourceSecurityIdentityBasic(identityName string) string {
	return fmt.Sprintf(`
	data "keyfactor_identity" "test" {
		account_name = "%s"
	}
	`, identityName)
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorIdentityDataSource tests the keyfactor_identity data source
// using VCR cassettes (no lab required for replay).
// Recording requires a lab with Active Directory integration; the test is skipped
// in replay mode if no cassette has been recorded.
func TestUnitKeyfactorIdentityDataSource(t *testing.T) {
	cassetteName := "security_identity_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var accountName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		client := newTestClient(t)
		accountName = discoverSecurityIdentity(t, client)
		if accountName == "" {
			t.Skip("No security identity available for recording")
		}
		writeSecurityIdentityTestParams(cassettePath, securityIdentityTestParams{AccountName: accountName})
	} else {
		params := readSecurityIdentityTestParams(cassettePath)
		if params.AccountName == "" {
			t.Skip("No security identity params recorded; skipping (requires AD lab to record)")
		}
		accountName = params.AccountName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	dataSourceName := "data.keyfactor_identity.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorDataSourceSecurityIdentityBasic(accountName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceName, "id"),
					resource.TestCheckResourceAttrSet(dataSourceName, "account_name"),
					resource.TestCheckResourceAttrSet(dataSourceName, "identity_type"),
					resource.TestCheckResourceAttrSet(dataSourceName, "valid"),
					resource.TestCheckResourceAttrSet(dataSourceName, "roles.#"),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorSecurityIdentityDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	accountName := discoverSecurityIdentity(t, client)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorDataSourceSecurityIdentityBasic(accountName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_identity.test", "id"),
					resource.TestCheckResourceAttrSet("data.keyfactor_identity.test", "account_name"),
					resource.TestCheckResourceAttrSet("data.keyfactor_identity.test", "roles.#"),
					resource.TestCheckResourceAttrSet("data.keyfactor_identity.test", "identity_type"),
					resource.TestCheckResourceAttrSet("data.keyfactor_identity.test", "valid"),
				),
			},
		},
	})
}
