package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorOAuthSecurityClaimDataSource(t *testing.T) {
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
	var resourceType = "keyfactor_oauth_security_claim"
	var resourceName = fmt.Sprintf("data.%s.test", resourceType)

	securityClaimType := getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_CLAIM_TYPE")
	securityClaimValue := getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_CLAIM_VALUE")
	securityClaimAuthScheme := getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccDataSourceKeyfactorOAuthSecurityClaim(resourceType, securityClaimType, securityClaimValue, securityClaimAuthScheme),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "description"),
					resource.TestCheckResourceAttrSet(resourceName, "provider.%"),
					resource.TestCheckResourceAttr(resourceName, "claim_type", securityClaimType),
					resource.TestCheckResourceAttr(resourceName, "claim_value", securityClaimValue),
					resource.TestCheckResourceAttr(resourceName, "provider_authentication_scheme", securityClaimAuthScheme),
				),
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorOAuthSecurityClaimDataSource tests the
// keyfactor_oauth_security_claim data source using VCR cassettes.
func TestUnitKeyfactorOAuthSecurityClaimDataSource(t *testing.T) {
	cassetteName := "oauth_security_claim_data_source"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var claimValue, authScheme string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		claimValue = fmt.Sprintf("tf-unit-claim-ds-%d", time.Now().UnixNano()%1000000000)
		authScheme = discoverOAuthAuthScheme(t, newTestClient(t))
		writeOAuthClaimRecordTestParams(cassettePath, oauthClaimRecordTestParams{
			ClaimValue: claimValue,
			AuthScheme: authScheme,
		})
	} else {
		params := readOAuthClaimRecordTestParams(cassettePath)
		claimValue = params.ClaimValue
		authScheme = params.AuthScheme
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	claimType := "OAuthSubject"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "keyfactor_oauth_security_claim" "unit_ds_setup" {
	claim_type                     = %q
	claim_value                    = %q
	provider_authentication_scheme = %q
	description                    = "Unit test claim for data source"
}

data "keyfactor_oauth_security_claim" "test" {
	claim_type                     = keyfactor_oauth_security_claim.unit_ds_setup.claim_type
	claim_value                    = keyfactor_oauth_security_claim.unit_ds_setup.claim_value
	provider_authentication_scheme = keyfactor_oauth_security_claim.unit_ds_setup.provider_authentication_scheme
}
`, claimType, claimValue, authScheme),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_claim.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_claim.test", "claim_type", claimType),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_claim.test", "claim_value", claimValue),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_claim.test", "provider_authentication_scheme", authScheme),
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_claim.test", "description"),
				),
			},
		},
	})
}

func testAccDataSourceKeyfactorOAuthSecurityClaim(resourceName string, claimType string, claimValue string, providerAuthScheme string) string {
	output := fmt.Sprintf(`
	data "%s" "test" {
		claim_type = "%s"
  		claim_value = "%s"
		provider_authentication_scheme = "%s"
	}
	`, resourceName, claimType, claimValue, providerAuthScheme)
	return output
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorOAuthSecurityClaimDataSource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	authScheme := discoverOAuthAuthScheme(t, client)
	claimType := "OAuthSubject"
	claimValue := acctest.RandomWithPrefix("tf-int-claim-ds")

	// Create a claim resource first, then read it back via data source
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "keyfactor_oauth_security_claim" "int_ds_setup" {
	claim_type                    = "%s"
	claim_value                   = "%s"
	provider_authentication_scheme = "%s"
	description                   = "Integration test claim for data source"
}

data "keyfactor_oauth_security_claim" "test" {
	claim_type                    = keyfactor_oauth_security_claim.int_ds_setup.claim_type
	claim_value                   = keyfactor_oauth_security_claim.int_ds_setup.claim_value
	provider_authentication_scheme = keyfactor_oauth_security_claim.int_ds_setup.provider_authentication_scheme
}
`, claimType, claimValue, authScheme),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_oauth_security_claim.test", "id"),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_claim.test", "claim_type", claimType),
					resource.TestCheckResourceAttr("data.keyfactor_oauth_security_claim.test", "claim_value", claimValue),
				),
			},
		},
	})
}
