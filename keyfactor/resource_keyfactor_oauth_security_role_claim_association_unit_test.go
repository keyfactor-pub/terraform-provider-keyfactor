package keyfactor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	kfsdk "github.com/Keyfactor/keyfactor-go-client-sdk/v24"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// oauthRoleClaimAssocMockAuthConfig implements the structurally-equivalent
// AuthConfig interfaces required by the keyfactor-go-client-sdk v1 and v2 API
// clients (Authenticate, GetHttpClient, GetServerConfig), backed by an
// httptest server. Host is the bare "host:port" (no scheme) because the SDK's
// prepareRequest sets url.Host directly from GetServerConfig().Host and forces
// url.Scheme = "https" itself.
type oauthRoleClaimAssocMockAuthConfig struct {
	server *httptest.Server
}

func (m *oauthRoleClaimAssocMockAuthConfig) GetServerConfig() *auth_providers.Server {
	return &auth_providers.Server{
		Host:          strings.TrimPrefix(m.server.URL, "https://"),
		SkipTLSVerify: true,
	}
}

func (m *oauthRoleClaimAssocMockAuthConfig) GetHttpClient() (*http.Client, error) {
	return m.server.Client(), nil
}

func (m *oauthRoleClaimAssocMockAuthConfig) Authenticate() error { return nil }

func newOAuthRoleClaimAssocMockClient(server *httptest.Server) *kfsdk.APIClient {
	return kfsdk.NewAPIClientWithAuth(&oauthRoleClaimAssocMockAuthConfig{server: server})
}

// roleResponseBody builds a /Security/Roles/{id} GET response body with Name,
// Description, and PermissionSetId all null, and an empty Claims list (so
// mapOAuthSecurityClaimsFromRole's separate claim.Provider dereference, a
// different bug, is never exercised by this test).
func nullFieldsRoleResponseBody(roleId int32) string {
	return fmt.Sprintf(`{
		"Id": %d,
		"Name": null,
		"Description": null,
		"EmailAddress": null,
		"Immutable": false,
		"PermissionSetId": null,
		"Permissions": [],
		"Claims": []
	}`, roleId)
}

// validClaimResponseBody builds a /Security/Claims/{id} GET response body with
// all fields the Create() path dereferences (ClaimType, ClaimValue, Provider,
// Description) populated, so the claim-side code (a separate, out-of-scope
// nil-deref risk) never panics in this test — isolating the assertion to the
// role Name/Description/PermissionSetId dereference under test.
func validClaimResponseBody(claimId int32) string {
	return fmt.Sprintf(`{
		"Id": %d,
		"Description": "a test claim",
		"ClaimType": "OAuthSubject",
		"ClaimValue": "test-subject",
		"Provider": {"Id": "1", "AuthenticationScheme": "System", "DisplayName": "System"}
	}`, claimId)
}

// TestUnitOAuthSecurityRoleClaimAssociation_CreateNullRoleFieldsDoesNotPanic is
// the red/green regression test for the nil-pointer dereference in
// resourceOAuthSecurityRoleClaimAssociation.Create: after fetching the role,
// the code built the update request with `*remoteRoleState.Name.Get()`,
// `*remoteRoleState.Description.Get()`, and `*remoteRoleState.PermissionSetId`
// with no nil check. A role whose Name/Description/PermissionSetId are
// actually null on the server (as constructed here) panics.
func TestUnitOAuthSecurityRoleClaimAssociation_CreateNullRoleFieldsDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	const (
		roleId  int32 = 42
		claimId int32 = 7
	)

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Security/Roles/%d", roleId), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(nullFieldsRoleResponseBody(roleId)))
	})
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Security/Claims/%d", claimId), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validClaimResponseBody(claimId)))
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		// PUT to update the role. Only reached once the nil-deref is fixed;
		// return a well-formed response so the fixed Create() completes cleanly.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(nullFieldsRoleResponseBody(roleId)))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	sdkClient := newOAuthRoleClaimAssocMockClient(server)

	schema, sDiags := resourceOAuthSecurityRoleClaimAssociationType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	plan := OAuthSecurityRoleClaimAssociation{
		ID:      types.String{Unknown: true},
		RoleID:  types.Int64{Value: int64(roleId)},
		ClaimID: types.Int64{Value: int64(claimId)},
	}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	r := resourceOAuthSecurityRoleClaimAssociation{p: provider{configured: true, sdkClient: sdkClient}}

	req := tfsdk.CreateResourceRequest{Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	// The whole point of this regression test: Create must NOT panic when the
	// role's Name/Description/PermissionSetId are null.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Create panicked (nil-deref regression): %v", rec)
			}
		}()
		r.Create(ctx, req, resp)
	}()

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected Create to succeed with null role Name/Description/PermissionSetId, got diagnostics: %+v", resp.Diagnostics)
	}
}

// TestUnitOAuthSecurityRoleClaimAssociation_DeleteNullRoleFieldsDoesNotPanic is
// the Delete-path counterpart: the same nil-deref pattern exists when building
// the update request that removes the claim from the role.
func TestUnitOAuthSecurityRoleClaimAssociation_DeleteNullRoleFieldsDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	const (
		roleId  int32 = 43
		claimId int32 = 999
	)

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Security/Roles/%d", roleId), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(nullFieldsRoleResponseBody(roleId)))
	})
	mux.HandleFunc("/KeyfactorAPI/Security/Roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(nullFieldsRoleResponseBody(roleId)))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	sdkClient := newOAuthRoleClaimAssocMockClient(server)

	schema, sDiags := resourceOAuthSecurityRoleClaimAssociationType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	state := OAuthSecurityRoleClaimAssociation{
		ID:      types.String{Value: fmt.Sprintf("%d/%d", roleId, claimId)},
		RoleID:  types.Int64{Value: int64(roleId)},
		ClaimID: types.Int64{Value: int64(claimId)},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceOAuthSecurityRoleClaimAssociation{p: provider{configured: true, sdkClient: sdkClient}}

	req := tfsdk.DeleteResourceRequest{State: stateObj}
	resp := &tfsdk.DeleteResourceResponse{State: stateObj}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Delete panicked (nil-deref regression): %v", rec)
			}
		}()
		r.Delete(ctx, req, resp)
	}()

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected Delete to succeed with null role Name/Description/PermissionSetId, got diagnostics: %+v", resp.Diagnostics)
	}
}
