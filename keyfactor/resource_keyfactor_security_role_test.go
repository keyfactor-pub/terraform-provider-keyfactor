package keyfactor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/stretchr/testify/assert"
)

// securityRoleMockAuthConfig implements api.AuthConfig for httptest-backed
// unit tests of the security role resource's Update path (mirrors
// certUpdateMockAuthConfig in resource_keyfactor_certificate_unit_test.go).
type securityRoleMockAuthConfig struct {
	server *httptest.Server
}

func (m *securityRoleMockAuthConfig) GetServerConfig() *auth_providers.Server {
	return &auth_providers.Server{
		Host:          m.server.URL,
		APIPath:       "KeyfactorAPI",
		SkipTLSVerify: true,
	}
}

func (m *securityRoleMockAuthConfig) GetHttpClient() (*http.Client, error) {
	return m.server.Client(), nil
}

func (m *securityRoleMockAuthConfig) Authenticate() error       { return nil }
func (m *securityRoleMockAuthConfig) GetCommandVersion() string { return "25.1.0.0" }

type roleTestCase struct {
	name           string
	description    string
	permissions    []string
	permissionsStr string
	resourceName   string
}

func TestAccKeyfactorRoleResource(t *testing.T) {

	t.Skip("TestAcc* tests disabled - legacy SDKv2 harness")
	r := roleTestCase{
		name:        os.Getenv("KEYFACTOR_SECURITY_ROLE_NAME"),
		description: "Role used for a Terraform.",
		permissions: []string{
			"AdminPortal:Read",
			"API:Read",
		},
		resourceName: "keyfactor_role.terraform_test",
	}
	pStr, _ := json.Marshal(r.permissions)
	r.permissionsStr = string(pStr)

	// Update to multiple roles test
	r2 := r
	additionalPermissions := []string{
		"Certificates:Read",
		"Certificates:EditMetadata",
		"Certificates:Import",
		"Certificates:Recover",
		"Certificates:Revoke",
		"Certificates:Delete",
		"Certificates:ImportPrivateKey",
		"CertificateCollections:Modify",
		"PkiManagement:Read",
		"PkiManagement:Modify",
		"CertificateStoreManagement:Read",
		"CertificateStoreManagement:Modify",
		"CertificateStoreManagement:Schedule",
		"CertificateEnrollment:EnrollPFX",
		"CertificateEnrollment:EnrollCSR",
		"CertificateEnrollment:CsrGeneration",
		"CertificateEnrollment:PendingCsr",
	}
	r2.permissions = append(r2.permissions, additionalPermissions...)
	r2Str, _ := json.Marshal(r2.permissions)
	r2.permissionsStr = string(r2Str)

	// Update to no roles test
	r3 := r2
	r3.permissions = []string{}
	r3Str, _ := json.Marshal(r3.permissions)
	r3.permissionsStr = string(r3Str)

	// Testing Role
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				//ResourceName: "",
				//PreConfig:    nil,
				//Taint:        nil,
				Config: testAccKeyfactorRoleResourceConfig(r),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r.resourceName, "name"),          // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "permissions.0"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r.resourceName, "permissions.1"), // TODO: Check specific value

				),
				//Destroy:                   false,
				//ExpectNonEmptyPlan:        false,
				//ExpectError:               nil,
				//PlanOnly:                  false,
				//PreventDiskCleanup:        false,
				//PreventPostDestroyRefresh: false,
				//SkipFunc:                  nil,
				//ImportState:               false,
				//ImportStateId:             "",
				//ImportStateIdPrefix:       "",
				//ImportStateIdFunc:         nil,
				//ImportStateCheck:          nil,
				//ImportStateVerify:         false,
				//ImportStateVerifyIgnore:   nil,
				//ProviderFactories:         nil,
				//ProtoV5ProviderFactories:  nil,
				//ProtoV6ProviderFactories:  nil,
				//ExternalProviders:         nil,
			},
			// ImportState testing
			//{
			//	ResourceName:      "scaffolding_example.test",
			//	ImportState:       false,
			//	ImportStateVerify: false,
			//	// This is not normally necessary, but is here because this
			//	// example code does not have an actual upstream service.
			//	// Once the Read method is able to refresh information from
			//	// the upstream service, this can be removed.
			//	ImportStateVerifyIgnore: []string{"configurable_attribute"},
			//},
			// Update and Read testing
			{
				Config: testAccKeyfactorRoleResourceConfig(r2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r2.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r2.resourceName, "name"),          // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.0"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.1"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.3"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r2.resourceName, "permissions.4"), // TODO: Check specific value
				),
			},
			{
				Config: testAccKeyfactorRoleResourceConfig(r3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(r3.resourceName, "id"),
					resource.TestCheckResourceAttrSet(r3.resourceName, "name"), // TODO: Check specific value
					resource.TestCheckResourceAttrSet(r3.resourceName, "permissions.#"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// ---------------------------------------------------------------------------
// Unit tests (VCR cassettes)
// ---------------------------------------------------------------------------

// TestUnitKeyfactorSecurityRoleResource tests the keyfactor_role resource
// create/update lifecycle using VCR cassettes (no lab required for replay).
func TestUnitKeyfactorSecurityRoleResource(t *testing.T) {
	cassetteName := "security_role_resource"
	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)

	var roleName string
	if os.Getenv("RECORD_CASSETTES") == "1" {
		roleName = fmt.Sprintf("tf-unit-role-%d", time.Now().UnixNano()%1000000000)
		writeSecurityRoleTestParams(cassettePath, securityRoleTestParams{RoleName: roleName})
	} else {
		params := readSecurityRoleTestParams(cassettePath)
		roleName = params.RoleName
	}

	factories, cleanup := newVCRProviderFactories(t, cassetteName)
	defer cleanup()

	resourceName := "keyfactor_role.unit_test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "unit_test" {
	name        = %q
	description = "Unit test role"
	permissions = []
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "description", "Unit test role"),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "0"),
				),
			},
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "unit_test" {
	name        = %q
	description = "Unit test role updated"
	permissions = distinct(sort(["Certificates:Read", "Certificates:EditMetadata"]))
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "description", "Unit test role updated"),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "permissions.0", "Certificates:EditMetadata"),
					resource.TestCheckResourceAttr(resourceName, "permissions.1", "Certificates:Read"),
				),
			},
		},
	})
}

// TestUnitKeyfactorSecurityRoleResource_UpdateOmittingPermissionsPreservesThem
// drives a REAL Terraform Core plan/apply/refresh cycle (resource.UnitTest +
// ProtoV6ProviderFactories, the same shape as TestUnitKeyfactorIdentityResource
// in resource_keyfactor_security_identity_test.go) reproducing the exact
// scenario found validating PR179 live against a real lab:
//
//  1. Create a role with permissions declared in config.
//  2. Apply again with an unrelated attribute (description) changed and
//     `permissions` omitted from config entirely.
//
// This must NOT fail with "Provider produced inconsistent result after
// apply" -- permissions is Optional+Computed with a UseStateForUnknown plan
// modifier, so Terraform Core commits at plan time (step 2) to the prior
// state's permissions value; if Update() then returns anything else, Core
// itself rejects the apply. And the resulting state must show permissions
// genuinely preserved server-side, not silently cleared -- the full-replace
// PUT fix in buildSecurityRoleUpdateArg (see its doc comment in
// resource_keyfactor_security_role.go).
//
// Unlike TestUnitKeyfactorSecurityRoleResource above, this test is backed by
// a hand-built httptest mock server, not a VCR cassette: makeVCRMatcher
// matches replayed interactions on method+path+query ONLY (see its doc
// comment in test_helpers_test.go) -- it deliberately ignores request
// bodies, so a cassette replay can never assert what body the provider
// actually sent, only script what the mock server responds with regardless.
// The mock server here inspects the real PUT request body Update() sends and
// mimics Command's actual full-replace semantics (confirmed live against
// int25-4-1.kftestlab.com while validating PR179): an absent OR null
// "Permissions" key clears permissions to [] server-side; it is never
// treated as "leave unchanged".
//
// Red/green: reverting resource_keyfactor_security_role.go's
// buildSecurityRoleUpdateArg to the pre-fix 3-argument form (no
// statePermissions fallback -- see commit a0cd2f5) makes step 2's PUT body
// omit "Permissions" entirely. The mock server mimics Command by clearing
// permissions to [] in that case, which the schema's UseStateForUnknown
// modifier already committed Core to expect as ["Certificates:Read"] --
// Terraform Core itself then fails step 2's apply with "Provider produced
// inconsistent result after apply: .permissions: was ..., but now ...",
// exactly the class of bug this test guards against. This was confirmed by
// temporarily stashing the fix and re-running this test.
func TestUnitKeyfactorSecurityRoleResource_UpdateOmittingPermissionsPreservesThem(t *testing.T) {
	const roleID = 4242
	roleName := "tf-unit-role-preserve-perms"

	// currentPermissions/currentDescription model the mock server's
	// persisted role state across the two apply steps below, so GET
	// (refresh) always reflects the most recent POST/PUT.
	currentPermissions := []string{"Certificates:Read"}
	currentDescription := "Initial description"

	var lastPutBody map[string]interface{}
	sawPermissionsKeyOnLastPut := false

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var body struct {
				Name        string    `json:"Name"`
				Description string    `json:"Description"`
				Permissions *[]string `json:"Permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			currentDescription = body.Description
			if body.Permissions != nil {
				currentPermissions = *body.Permissions
			} else {
				currentPermissions = []string{}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Id":          roleID,
				"Name":        roleName,
				"Description": currentDescription,
				"Permissions": currentPermissions,
			})
		case http.MethodPut:
			raw, _ := io.ReadAll(r.Body)

			var rawMap map[string]interface{}
			_ = json.Unmarshal(raw, &rawMap)
			lastPutBody = rawMap
			_, sawPermissionsKeyOnLastPut = rawMap["Permissions"]

			// Mimic Command's real PUT /Security/Roles full-replace
			// semantics: an absent OR null Permissions key clears
			// permissions to [] -- it is never "leave unchanged".
			var decoded struct {
				Description string    `json:"Description"`
				Permissions *[]string `json:"Permissions"`
			}
			_ = json.Unmarshal(raw, &decoded)
			currentDescription = decoded.Description
			if decoded.Permissions != nil {
				currentPermissions = *decoded.Permissions
			} else {
				currentPermissions = []string{}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Id":          roleID,
				"Name":        roleName,
				"Description": currentDescription,
				"Permissions": currentPermissions,
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Security/Roles/%d", roleID), func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Id":          roleID,
				"Name":        roleName,
				"Description": currentDescription,
				"Permissions": currentPermissions,
			})
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewTLSServer(mux)
	defer server.Close()

	p := &provider{testAuth: &securityRoleMockAuthConfig{server: server}}
	factories := map[string]func() (tfprotov6.ProviderServer, error){
		"keyfactor": providerserver.NewProtocol6WithError(p),
	}

	resourceName := "keyfactor_role.preserve_perms"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			// Step 1: create with permissions declared in config.
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "preserve_perms" {
	name        = %q
	description = "Initial description"
	permissions = ["Certificates:Read"]
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "description", "Initial description"),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "permissions.0", "Certificates:Read"),
				),
			},
			// Step 2: change an unrelated attribute (description) and omit
			// `permissions` from config entirely. Must NOT fail with
			// "Provider produced inconsistent result after apply", and
			// permissions must still be ["Certificates:Read"] afterward --
			// not cleared.
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "preserve_perms" {
	name        = %q
	description = "Updated description, unrelated to permissions"
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description, unrelated to permissions"),
					resource.TestCheckResourceAttr(resourceName, "permissions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "permissions.0", "Certificates:Read"),
				),
			},
		},
	})

	if lastPutBody == nil {
		t.Fatalf("expected the mock PUT /Security/Roles endpoint to have captured a request body, got none")
	}
	if !sawPermissionsKeyOnLastPut {
		t.Fatalf(
			"step 2's PUT /Security/Roles request omitted the \"Permissions\" key entirely -- Command's PUT " +
				"endpoint is a full-replace, so omitting the field (not just sending null) clears the role's " +
				"permissions server-side; buildSecurityRoleUpdateArg must resend state.Permissions explicitly " +
				"when config.Permissions is undeclared",
		)
	}

	var gotPermissions []string
	if permsValue, ok := lastPutBody["Permissions"].([]interface{}); ok {
		for _, v := range permsValue {
			if s, ok := v.(string); ok {
				gotPermissions = append(gotPermissions, s)
			}
		}
	}
	assert.Equal(
		t, []string{"Certificates:Read"}, gotPermissions,
		"step 2's PUT body must explicitly resend the role's prior permissions, not send null/omit the field",
	)
}

func testAccKeyfactorRoleResourceConfig(t roleTestCase) string {
	output := fmt.Sprintf(`
resource "keyfactor_role" "terraform_test" {
	name = "%s"
	description  = "%s"
	permissions  = distinct(sort(%s))
}
`, t.name, t.description, t.permissionsStr)
	return output
}

// ---------------------------------------------------------------------------
// Integration tests (auto-discovery)
// ---------------------------------------------------------------------------

func TestIntKeyfactorRoleResource(t *testing.T) {
	testAccIntegrationPreCheck(t)

	roleName := fmt.Sprintf("tf-int-test-%d", time.Now().UnixNano())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with no permissions
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "int_test" {
	name        = "%s"
	description = "Integration test role"
	permissions = []
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_role.int_test", "id"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "name", roleName),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "description", "Integration test role"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "permissions.#", "0"),
				),
			},
			// Update: add permissions
			{
				Config: fmt.Sprintf(`
resource "keyfactor_role" "int_test" {
	name        = "%s"
	description = "Integration test role updated"
	permissions = distinct(sort(["Certificates:Read", "Certificates:EditMetadata"]))
}
`, roleName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("keyfactor_role.int_test", "id"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "description", "Integration test role updated"),
					resource.TestCheckResourceAttr("keyfactor_role.int_test", "permissions.#", "2"),
				),
			},
		},
	})
}
