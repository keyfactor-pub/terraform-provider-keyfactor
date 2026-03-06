package keyfactor

import (
	"fmt"
	"os"
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
