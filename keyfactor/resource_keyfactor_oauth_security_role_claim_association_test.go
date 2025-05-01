package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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

func TestAccKeyfactorOAuthSecurityRoleClaimAssociationImportState(t *testing.T) {
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

	roleResourcePath := fmt.Sprintf("%s.%s", "keyfactor_oauth_security_role", "test_role_1")
	claimResourcePath := fmt.Sprintf("%s.%s", "keyfactor_oauth_security_claim", "test_claim")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read and Create role
			{
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResource(r),
			}, // Import State
			{
				ResourceName:      r.resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(state *terraform.State) (string, error) {
					roleId, err := getResourceIdFromTerraformState(state, roleResourcePath)
					if err != nil {
						return "", err
					}

					claimId, err := getResourceIdFromTerraformState(state, claimResourcePath)
					if err != nil {
						return "", err
					}

					return fmt.Sprintf("%s/%s", roleId, claimId), nil
				},
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
