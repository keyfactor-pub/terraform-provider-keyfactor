package keyfactor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
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

	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
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

// TestUnitKeyfactorOAuthSecurityRoleClaimAssociationResource_Import tests the
// import lifecycle using VCR cassettes. Step 1 creates the association; Step 2
// imports it by composite ID "<roleId>/<claimId>" and verifies state.
//
// To record cassettes:
//
//	RECORD_CASSETTES=1 make testunit-record-one TEST_NAME=TestUnitKeyfactorOAuthSecurityRoleClaimAssociationResource_Import
func TestUnitKeyfactorOAuthSecurityRoleClaimAssociationResource_Import(t *testing.T) {
	cassetteName := "oauth_security_role_claim_association_resource_import"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var roleName1, claimValue string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		ts := time.Now().UnixNano() % 1000000000
		roleName1 = fmt.Sprintf("tf-unit-role-assoc-imp1-%d", ts)
		claimValue = fmt.Sprintf("tf-unit-claim-assoc-imp-%d", ts)
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
				// Step 1: Create the association.
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResourceSingle(roleName1, claimValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourcePath, "id"),
					resource.TestCheckResourceAttrSet(resourcePath, "role_id"),
					resource.TestCheckResourceAttrSet(resourcePath, "claim_id"),
				),
			},
			{
				// Step 2: Import by composite ID "<roleId>/<claimId>" and verify.
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorOAuthSecurityRoleClaimAssociationResource(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	authScheme := discoverOAuthAuthScheme(t, client)
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

// TestIntKeyfactorOAuthSecurityRoleClaimAssociationResource_Import verifies that
// an existing role-claim association can be imported by its composite ID and that
// state is fully populated after import.
func TestIntKeyfactorOAuthSecurityRoleClaimAssociationResource_Import(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	authScheme := discoverOAuthAuthScheme(t, client)
	_ = authScheme

	r := oauthSecurityRoleClaimAssociationTestCase{
		role1Name:           acctest.RandomWithPrefix("tf-int-role-imp"),
		claimValue:          acctest.RandomWithPrefix("tf-int-claim-imp"),
		claimProviderScheme: authScheme,
		resourceType:        "keyfactor_oauth_security_role_claim_association",
		resourceName:        "test_role_claim_association",
		resourcePath:        "keyfactor_oauth_security_role_claim_association.test_role_claim_association",
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create the association.
				Config: testAccKeyfactorOAuthSecurityRoleClaimAssociationResourceSingle(r.role1Name, r.claimValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourcePath, "id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "role_id"),
					resource.TestCheckResourceAttrSet(r.resourcePath, "claim_id"),
				),
			},
			{
				// Step 2: Import by composite ID "<roleId>/<claimId>" and verify
				// that role_id and claim_id are correctly re-populated.
				ResourceName:      r.resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Multi-claim association tests — regression path for role Update preserving claims
// ---------------------------------------------------------------------------

// testAccOAuthRoleClaimAssocMultiConfig creates 1 role + 2 claims + 2 associations.
// Used for both create and update steps; description changes between steps.
func testAccOAuthRoleClaimAssocMultiConfig(roleName, roleDesc, claimValue1, claimValue2 string) string {
	return fmt.Sprintf(`
data "keyfactor_permission_set" "global_permission_set" {
	name = "Global"
}

resource "keyfactor_oauth_security_role" "multi_test_role" {
	name              = "%s"
	description       = "%s"
	permission_set_id = data.keyfactor_permission_set.global_permission_set.id
	email_address     = "multi-claim-test@example.com"
	permissions       = []
}

resource "keyfactor_oauth_security_claim" "multi_test_claim_1" {
	claim_type                     = "OAuthClientId"
	claim_value                    = "%s"
	provider_authentication_scheme = "System"
	description                    = "Multi-claim test claim 1"
}

resource "keyfactor_oauth_security_claim" "multi_test_claim_2" {
	claim_type                     = "OAuthClientId"
	claim_value                    = "%s"
	provider_authentication_scheme = "System"
	description                    = "Multi-claim test claim 2"

	depends_on = [keyfactor_oauth_security_claim.multi_test_claim_1]
}

resource "keyfactor_oauth_security_role_claim_association" "multi_assoc_1" {
	role_id  = resource.keyfactor_oauth_security_role.multi_test_role.id
	claim_id = resource.keyfactor_oauth_security_claim.multi_test_claim_1.id
}

resource "keyfactor_oauth_security_role_claim_association" "multi_assoc_2" {
	role_id  = resource.keyfactor_oauth_security_role.multi_test_role.id
	claim_id = resource.keyfactor_oauth_security_claim.multi_test_claim_2.id

	depends_on = [keyfactor_oauth_security_role_claim_association.multi_assoc_1]
}
`, roleName, roleDesc, claimValue1, claimValue2)
}

// TestUnitKeyfactorOAuthSecurityRoleClaimAssociation_MultiClaim verifies that
// updating a role's description does not silently wipe claim associations.
// This is the critical regression test for the fix where role Update now reads
// existing claims from the server before issuing the PUT.
//
// To record cassettes:
//
//	RECORD_CASSETTES=1 make testunit-record-one TEST_NAME=TestUnitKeyfactorOAuthSecurityRoleClaimAssociation_MultiClaim
func TestUnitKeyfactorOAuthSecurityRoleClaimAssociation_MultiClaim(t *testing.T) {
	cassetteName := "oauth_security_role_claim_assoc_multi"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var roleName, claimValue1, claimValue2 string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		ts := time.Now().UnixNano() % 1000000000
		roleName = fmt.Sprintf("tf-unit-multi-assoc-%d", ts)
		claimValue1 = uuid.New().String()
		claimValue2 = uuid.New().String()
		writeOAuthMultiAssocTestParams(cassettePath, oauthMultiAssocTestParams{
			RoleName:    roleName,
			ClaimValue1: claimValue1,
			ClaimValue2: claimValue2,
		})
	} else {
		params := readOAuthMultiAssocTestParams(cassettePath)
		roleName = params.RoleName
		claimValue1 = params.ClaimValue1
		claimValue2 = params.ClaimValue2
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	assoc1Path := "keyfactor_oauth_security_role_claim_association.multi_assoc_1"
	assoc2Path := "keyfactor_oauth_security_role_claim_association.multi_assoc_2"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create role + 2 claims + 2 associations
				Config: testAccOAuthRoleClaimAssocMultiConfig(roleName, "Initial description", claimValue1, claimValue2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(assoc1Path, "id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "claim_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "claim_id"),
				),
			},
			{
				// Step 2: Update role description — both associations must survive
				Config: testAccOAuthRoleClaimAssocMultiConfig(roleName, "Updated description", claimValue1, claimValue2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(assoc1Path, "id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "claim_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "claim_id"),
				),
			},
		},
	})
}

// TestIntKeyfactorOAuthSecurityRoleClaimAssociation_MultiClaim is the integration
// variant of the multi-claim regression test. It verifies against a live lab that
// updating a role's description preserves all claim associations.
func TestIntKeyfactorOAuthSecurityRoleClaimAssociation_MultiClaim(t *testing.T) {
	client := testAccIntegrationPreCheck(t)

	authScheme := discoverOAuthAuthScheme(t, client)
	_ = authScheme // HCL config hardcodes "System"; kept for documentation

	roleName := acctest.RandomWithPrefix("tf-int-multi-assoc")
	claimValue1 := uuid.New().String()
	claimValue2 := uuid.New().String()

	assoc1Path := "keyfactor_oauth_security_role_claim_association.multi_assoc_1"
	assoc2Path := "keyfactor_oauth_security_role_claim_association.multi_assoc_2"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create role + 2 claims + 2 associations
				Config: testAccOAuthRoleClaimAssocMultiConfig(roleName, "Initial description", claimValue1, claimValue2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(assoc1Path, "id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "claim_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "claim_id"),
				),
			},
			{
				// Step 2: Update role description — both associations must survive
				Config: testAccOAuthRoleClaimAssocMultiConfig(roleName, "Updated description", claimValue1, claimValue2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(assoc1Path, "id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc1Path, "claim_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "role_id"),
					resource.TestCheckResourceAttrSet(assoc2Path, "claim_id"),
				),
			},
		},
	})
}
