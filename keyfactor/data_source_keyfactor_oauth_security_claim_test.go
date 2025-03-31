package keyfactor

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccKeyfactorOAuthSecurityClaimDataSource(t *testing.T) {
	var resourceType = "keyfactor_oauth_security_claim"
	var resourceName = fmt.Sprintf("data.%s.test", resourceType)

	securityClaimType := os.Getenv("KEYFACTOR_OAUTH_SECURITY_CLAIM_TYPE")
	securityClaimValue := os.Getenv("KEYFACTOR_OAUTH_SECURITY_CLAIM_VALUE")
	securityClaimAuthScheme := os.Getenv("KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME")

	if securityClaimType == "" ||
		securityClaimValue == "" ||
		securityClaimAuthScheme == "" {
		t.Skip("Skipping test due to missing environment variables: KEYFACTOR_OAUTH_SECURITY_CLAIM_TYPE, KEYFACTOR_OAUTH_SECURITY_CLAIM_VALUE, KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME are all required")
	}

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
