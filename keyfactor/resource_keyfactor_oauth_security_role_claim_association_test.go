package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type oauthSecurityRoleClaimAssociationTestCase struct {
	roleName            string
	claimValue          string
	claimProviderScheme string
	resourceType        string
	resourceName        string
	resourcePath        string
}

func TestAccKeyfactorOAuthSecurityRoleClaimAssociationResource(t *testing.T) {

	r := oauthSecurityRoleClaimAssociationTestCase{
		roleName:            generateFakeName(10),
		claimValue:          generateFakeName(10),
		claimProviderScheme: "System",
		resourceType:        "keyfactor_oauth_security_role_claim_association",
		resourceName:        "test_role_claim_association",
		resourcePath:        "keyfactor_oauth_security_role_claim_association.test_role_claim_association",
	}

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
			// Delete testing automatically occurs in TestCase
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

resource "keyfactor_oauth_security_role" "test_role" {
	name = "%s"
	description  = "A Terraform test role"
	permission_set_id  = data.keyfactor_permission_set.global_permission_set.id
	email_address = "foo@example.com"
	permissions = []
}

resource "%s" "%s" {
	role_id = resource.keyfactor_oauth_security_role.test_role.id
	claim_id = resource.keyfactor_oauth_security_claim.test_claim.id
}
`,
		t.claimValue, t.roleName, t.resourceType, t.resourceName)
	return output
}
