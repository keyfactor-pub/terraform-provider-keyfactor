package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type oauthClaimTestCase struct {
	name               string
	description        string
	claimValue         string
	claimType          string
	providerAuthScheme string
	resourceType       string
	resourceName       string
	resourcePath       string
}

func TestAccKeyfactorOAuthClaimResource(t *testing.T) {

	r := oauthClaimTestCase{
		description:        "Terraform Create Claim",
		claimValue:         generateFakeName(10),
		claimType:          "OAuthSubject",
		providerAuthScheme: "System",
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "terraform_test",
		resourcePath:       "keyfactor_oauth_security_claim.terraform_test",
	}

	// Update to multiple claims test
	r2 := r
	r2.description = "Terraform Update Claim"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create claim
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttr(r.resourcePath, "description", r.description),
					resource.TestCheckResourceAttr(r.resourcePath, "claim_value", r.claimValue),
					resource.TestCheckResourceAttr(r.resourcePath, "claim_type", r.claimType),
				),
			},
			// Update claim
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(r2.resourcePath, "description", r2.description),
					resource.TestCheckResourceAttr(r2.resourcePath, "claim_type", r2.claimType),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccKeyfactorOAuthClaimResourceConfig(t oauthClaimTestCase) string {
	output := fmt.Sprintf(`
resource "%s" "%s" {
	claim_type = "%s"
	claim_value  = "%s"
	provider_authentication_scheme  = "%s"
	description = "%s"
}
`, t.resourceType, t.resourceName, t.claimType, t.claimValue, t.providerAuthScheme, t.description)
	return output
}
