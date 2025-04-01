package keyfactor

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

type oauthRoleTestCase struct {
	name         string
	description  string
	permissions  []string
	claims       []OAuthSecurityClaim
	emailAddress string
	resourceType string
	resourceName string
	resourcePath string
}

func TestAccKeyfactorOAuthRoleResource(t *testing.T) {

	r := oauthRoleTestCase{
		name:         generateFakeName(10),
		description:  "Terraform Create Role",
		permissions:  []string{"/metadata/types/read/"},
		claims:       []OAuthSecurityClaim{},
		emailAddress: "foo@example.com",
		resourceType: "keyfactor_oauth_security_role",
		resourceName: "terraform_test",
		resourcePath: "keyfactor_oauth_security_role.terraform_test",
	}

	c := oauthClaimTestCase{
		description:        "Terraform Claim",
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
			// Read and Create role
			{
				Config: testAccKeyfactorOAuthRoleResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "permission_set_id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "permissions.#"),
					resource.TestCheckResourceAttr(r.resourcePath, "name", r.name),
					resource.TestCheckResourceAttr(r.resourcePath, "description", r.description),
					resource.TestCheckResourceAttr(r.resourcePath, "email_address", r.emailAddress),
				),
			},
			// Update role
			{
				Config: testAccKeyfactorOAuthRoleResourceWithClaimConfig(c, r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "claims.#"),
					resource.TestCheckResourceAttr(r2.resourcePath, "description", r2.description),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccKeyfactorOAuthRoleResourceConfig(t oauthRoleTestCase) string {
	output := fmt.Sprintf(`	
data "keyfactor_permission_set" "global_permission_set" {
     name = "Global"
}

resource "%s" "%s" {
	name = "%s"
	description  = "%s"
	permission_set_id  = data.keyfactor_permission_set.global_permission_set.id
	email_address = "%s"
	permissions = ["%s"]
	claims = []
}
`, t.resourceType, t.resourceName, t.name, t.description, t.emailAddress, t.permissions[0])
	return output
}

func testAccKeyfactorOAuthRoleResourceWithClaimConfig(c oauthClaimTestCase, t oauthRoleTestCase) string {
	output := fmt.Sprintf(`
data "keyfactor_permission_set" "global_permission_set" {
     name = "Global"
}

resource "keyfactor_oauth_security_claim" "test_claim" {
	claim_type = "%s"
	claim_value = "%s"
	provider_authentication_scheme = "%s"
	description = "%s"
}

resource "%s" "%s" {
	name = "%s"
	description  = "%s"
	permission_set_id  = data.keyfactor_permission_set.global_permission_set.id
	email_address = "%s"
	permissions = []
	claims = [
	{
            description = resource.keyfactor_oauth_security_claim.test_claim.description
            claim_type = resource.keyfactor_oauth_security_claim.test_claim.claim_type
            claim_value = resource.keyfactor_oauth_security_claim.test_claim.claim_value
            provider_authentication_scheme = resource.keyfactor_oauth_security_claim.test_claim.provider_authentication_scheme
    }]
}
`,
		c.claimType, c.claimValue, c.providerAuthScheme, c.description,
		t.resourceType, t.resourceName, t.name, t.description, t.emailAddress)
	return output
}
