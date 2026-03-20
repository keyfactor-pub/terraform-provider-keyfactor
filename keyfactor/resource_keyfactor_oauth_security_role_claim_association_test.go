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

type oauthSecurityRoleClaimAssociationTestCase struct {
	role1Name              string
	role2Name              string
	associatedRoleResource string
	claimValue             string
	claimProviderScheme    string
	resourceType           string
	resourceName           string
	resourcePath           string
}

func TestAccKeyfactorOAuthSecurityRoleClaimAssociationResource(t *testing.T) {

	r := oauthSecurityRoleClaimAssociationTestCase{
		role1Name:              acctest.RandomWithPrefix("tf-acc-role"),
		role2Name:              acctest.RandomWithPrefix("tf-acc-role"),
		associatedRoleResource: "test_role_1",
		claimValue:             acctest.RandomWithPrefix("tf-acc-claim"),
		claimProviderScheme:    getEnvOrSkip(t, "KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME"),
		resourceType:           "keyfactor_oauth_security_role_claim_association",
		resourceName:           "test_role_claim_association",
		resourcePath:           "keyfactor_oauth_security_role_claim_association.test_role_claim_association",
	}

	r2 := r
	r2.associatedRoleResource = "test_role_2"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create role claim association
			{
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResource(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "role_id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "claim_id"),
				),
			},
			{
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResource(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "role_id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "claim_id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorOAuthSecurityRoleClaimAssociationResource tests the
// keyfactor_oauth_security_role_claim_association resource using VCR cassettes.
// Uses a single-role config to avoid non-deterministic POST ordering with two
// identical-URL requests that the VCR body-agnostic matcher cannot distinguish.
func TestUnitKeyfactorOAuthSecurityRoleClaimAssociationResource(t *testing.T) {
	cassetteName := "oauth_security_role_claim_association_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var roleName1, claimValue string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		ts := time.Now().UnixNano() % 1000000000
		roleName1 = fmt.Sprintf("tf-unit-role-assoc1-%d", ts)
		claimValue = fmt.Sprintf("tf-unit-claim-assoc-%d", ts)
		writeOAuthRoleClaimAssocTestParams(cassettePath, oauthRoleClaimAssocTestParams{
			RoleName1:  roleName1,
			ClaimValue: claimValue,
		})
	} else {
		params := readOAuthRoleClaimAssocTestParams(cassettePath)
		roleName1 = params.RoleName1
		claimValue = params.ClaimValue
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourcePath := "keyfactor_oauth_security_role_claim_association.test_role_claim_association"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResourceSingle(roleName1, claimValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourcePath, "id"),
					resource.TestCheckResourceAttrSet(resourcePath, "role_id"),
					resource.TestCheckResourceAttrSet(resourcePath, "claim_id"),
				),
			},
		},
	})
}

func testAccKeyfactorOAuthSecurityRoleClaimAssociationResource(t oauthSecurityRoleClaimAssociationTestCase) string {
	output := fmt.Sprintf(`
data "keyfactor_permission_set" "global_permission_set" {
     name = "Global"
}

resource "keyfactor_oauth_security_claim" "test_claim" {
	claim_type = "OAuthSubject"
	claim_value = "%s"
	provider_authentication_scheme = "System"
	description = "A Terraform test claim"
}

resource "keyfactor_oauth_security_role" "test_role_1" {
	name = "%s"
	description  = "A Terraform test role"
	permission_set_id  = data.keyfactor_permission_set.global_permission_set.id
	email_address = "foo@example.com"
	permissions = []
}

resource "keyfactor_oauth_security_role" "test_role_2" {
	name = "%s"
	description  = "A Terraform test role"
	permission_set_id  = data.keyfactor_permission_set.global_permission_set.id
	email_address = "foo@example.com"
	permissions = []
}

resource "%s" "%s" {
	role_id = resource.keyfactor_oauth_security_role.%s.id
	claim_id = resource.keyfactor_oauth_security_claim.test_claim.id
}
`,
		t.claimValue, t.role1Name, t.role2Name, t.resourceType, t.resourceName, t.associatedRoleResource)
	return output
}

// testAccKeyfactorOAuthSecurityRoleClaimAssociationResourceSingle is a
// single-role variant used by the unit test to avoid non-deterministic VCR
// replay when two identical-URL POSTs cannot be distinguished by the matcher.
func testAccKeyfactorOAuthSecurityRoleClaimAssociationResourceSingle(roleName, claimValue string) string {
	return fmt.Sprintf(`
data "keyfactor_permission_set" "global_permission_set" {
     name = "Global"
}

resource "keyfactor_oauth_security_claim" "test_claim" {
	claim_type = "OAuthSubject"
	claim_value = "%s"
	provider_authentication_scheme = "System"
	description = "A Terraform test claim"
}

resource "keyfactor_oauth_security_role" "test_role_1" {
	name = "%s"
	description  = "A Terraform test role"
	permission_set_id  = data.keyfactor_permission_set.global_permission_set.id
	email_address = "foo@example.com"
	permissions = []
}

resource "keyfactor_oauth_security_role_claim_association" "test_role_claim_association" {
	role_id  = resource.keyfactor_oauth_security_role.test_role_1.id
	claim_id = resource.keyfactor_oauth_security_claim.test_claim.id
}
`, claimValue, roleName)
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorOAuthSecurityRoleClaimAssociationResource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	authScheme := discoverOAuthAuthScheme(t)
	_ = authScheme // The existing HCL config hardcodes "System"; integration test reuses that config

	r := oauthSecurityRoleClaimAssociationTestCase{
		role1Name:              acctest.RandomWithPrefix("tf-int-role"),
		role2Name:              acctest.RandomWithPrefix("tf-int-role"),
		associatedRoleResource: "test_role_1",
		claimValue:             acctest.RandomWithPrefix("tf-int-claim"),
		claimProviderScheme:    authScheme,
		resourceType:           "keyfactor_oauth_security_role_claim_association",
		resourceName:           "test_role_claim_association",
		resourcePath:           "keyfactor_oauth_security_role_claim_association.test_role_claim_association",
	}

	// Swap to role 2
	r2 := r
	r2.associatedRoleResource = "test_role_2"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResource(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "role_id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "claim_id"),
				),
			},
			// Swap association to role 2
			{
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResource(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r2.resourcePath, "role_id"),
					resource.TestCheckResourceAttrSet(r2.resourcePath, "claim_id"),
				),
			},
		},
	})
}
