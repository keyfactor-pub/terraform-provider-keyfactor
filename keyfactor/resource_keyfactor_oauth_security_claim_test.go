package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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
		claimValue:         acctest.RandomWithPrefix("tf-acc-claim"),
		claimType:          "OAuthSubject",
		providerAuthScheme: getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME"),
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "terraform_test",
		resourcePath:       "keyfactor_oauth_security_claim.terraform_test",
	}

	// Update to claim test
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

func TestAccKeyfactorOAuthClaimResourceSucceedsIfProviderAuthSchemeUnknown(t *testing.T) {

	r := oauthClaimTestCase{
		description:        "Terraform Create Unknown Claim",
		claimValue:         acctest.RandomWithPrefix("tf-acc-claim"),
		claimType:          "OAuthSubject",
		providerAuthScheme: "unknown",
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "terraform_test",
		resourcePath:       "keyfactor_oauth_security_claim.terraform_test",
	}

	// Update to claim test
	r2 := r
	r2.description = "Terraform Update Unknown Claim"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create claim
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
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

func TestAccKeyfactorOAuthClaimResourceReplacesIfUneditableFieldsAreModified(t *testing.T) {

	r := oauthClaimTestCase{
		description:        "Terraform Create Unknown Claim",
		claimValue:         acctest.RandomWithPrefix("tf-acc-claim"),
		claimType:          "OAuthSubject",
		providerAuthScheme: getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME"),
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "terraform_test",
		resourcePath:       "keyfactor_oauth_security_claim.terraform_test",
	}

	r2 := r
	r2.claimType = "OAuthOid"

	r3 := r
	r3.claimValue = acctest.RandomWithPrefix("tf-acc-claim")

	r4 := r
	r4.providerAuthScheme = "unknown"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create claim
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
				),
			},
			// Check if claim type change took effect
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(r2.resourcePath, "claim_type", r2.claimType),
				),
			},
			// Check if claim value change took effect
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(r3.resourcePath, "claim_value", r3.claimValue),
				),
			},
			// Check if provider auth scheme change took effect
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r4),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(r4.resourcePath, "provider_authentication_scheme", r4.providerAuthScheme),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccKeyfactorOAuthClaimImportState(t *testing.T) {
	r := oauthClaimTestCase{
		description:        "Terraform Import Claim",
		claimValue:         acctest.RandomWithPrefix("tf-acc-claim"),
		claimType:          "OAuthSubject",
		providerAuthScheme: getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME"),
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "terraform_test",
		resourcePath:       "keyfactor_oauth_security_claim.terraform_test",
	}

	resourcePath := fmt.Sprintf("%s.%s", r.resourceType, r.resourceName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create role
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r),
			}, // Import State
			{
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					return getResourceIdFromTerraformState(state, resourcePath)
				},
			},
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
