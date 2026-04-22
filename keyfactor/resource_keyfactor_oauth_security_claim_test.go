package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

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

	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
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
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")

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
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")

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
	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
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

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorOAuthClaimResource tests the keyfactor_oauth_security_claim
// resource create/update lifecycle using VCR cassettes.
func TestUnitKeyfactorOAuthClaimResource(t *testing.T) {
	cassetteName := "oauth_security_claim_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var claimValue, authScheme string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		claimValue = fmt.Sprintf("tf-unit-claim-%d", time.Now().UnixNano()%1000000000)
		authScheme = discoverOAuthAuthScheme(t)
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

	r := oauthClaimTestCase{
		description:        "Unit test claim",
		claimValue:         claimValue,
		claimType:          "OAuthSubject",
		providerAuthScheme: authScheme,
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "unit_test",
		resourcePath:       "keyfactor_oauth_security_claim.unit_test",
	}
	r2 := r
	r2.description = "Unit test claim updated"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttr(r.resourcePath, "description", r.description),
					resource.TestCheckResourceAttr(r.resourcePath, "claim_value", r.claimValue),
					resource.TestCheckResourceAttr(r.resourcePath, "claim_type", r.claimType),
					resource.TestCheckResourceAttr(r.resourcePath, "provider_authentication_scheme", authScheme),
				),
			},
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourcePath, "id"),
					resource.TestCheckResourceAttr(r2.resourcePath, "description", r2.description),
					resource.TestCheckResourceAttr(r2.resourcePath, "claim_value", r2.claimValue),
					resource.TestCheckResourceAttr(r2.resourcePath, "claim_type", r2.claimType),
				),
			},
		},
	})
}

// TestUnitKeyfactorOAuthClaimResource_NilIdCreate verifies that the provider
// returns a diagnostic error (instead of panicking) when the API returns a
// response with a null Id on claim creation.
func TestUnitKeyfactorOAuthClaimResource_NilIdCreate(t *testing.T) {
	cassetteName := "oauth_security_claim_resource_nil_id_create"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	params := readOAuthClaimRecordTestParams(cassettePath)
	claimValue := params.ClaimValue
	authScheme := params.AuthScheme

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	r := oauthClaimTestCase{
		description:        "Unit test nil-id claim",
		claimValue:         claimValue,
		claimType:          "OAuthSubject",
		providerAuthScheme: authScheme,
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "nil_id_test",
		resourcePath:       "keyfactor_oauth_security_claim.nil_id_test",
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config:      testAccKeyfactorOAuthClaimResourceConfig(r),
				ExpectError: regexp.MustCompile(`(?i)nil|missing Id`),
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

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorOAuthClaimResource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	authScheme := discoverOAuthAuthScheme(t)

	r := oauthClaimTestCase{
		description:        "Integration test claim",
		claimValue:         acctest.RandomWithPrefix("tf-int-claim"),
		claimType:          "OAuthSubject",
		providerAuthScheme: authScheme,
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "int_test",
		resourcePath:       "keyfactor_oauth_security_claim.int_test",
	}

	r2 := r
	r2.description = "Integration test claim updated"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttr(r.resourcePath, "description", r.description),
					resource.TestCheckResourceAttr(r.resourcePath, "claim_value", r.claimValue),
					resource.TestCheckResourceAttr(r.resourcePath, "claim_type", r.claimType),
				),
			},
			// Update description
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourcePath, "id"),
					resource.TestCheckResourceAttr(r2.resourcePath, "description", r2.description),
					resource.TestCheckResourceAttr(r2.resourcePath, "claim_value", r2.claimValue),
				),
			},
		},
	})
}

func TestIntKeyfactorOAuthClaimResource_Import(t *testing.T) {
	testAccIntegrationPreCheck(t)

	authScheme := discoverOAuthAuthScheme(t)

	r := oauthClaimTestCase{
		description:        "Integration test claim import",
		claimValue:         acctest.RandomWithPrefix("tf-int-claim-imp"),
		claimType:          "OAuthSubject",
		providerAuthScheme: authScheme,
		resourceType:       "keyfactor_oauth_security_claim",
		resourceName:       "int_import_test",
		resourcePath:       "keyfactor_oauth_security_claim.int_import_test",
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorOAuthClaimResourceConfig(r),
			},
			{
				ResourceName:      r.resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					return getResourceIdFromTerraformState(state, r.resourcePath)
				},
			},
		},
	})
}
