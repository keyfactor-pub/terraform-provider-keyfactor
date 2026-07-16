package keyfactor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	kfsdk "github.com/Keyfactor/keyfactor-go-client-sdk/v24"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// newOAuthRoleClaimAssocMockClient builds a kfsdk.APIClient backed by an
// httptest server, for unit tests of the OAuth security role claim
// association resource. See mockAuthConfig / newSDKMockAuthConfig in
// test_helpers_test.go.
func newOAuthRoleClaimAssocMockClient(server *httptest.Server) *kfsdk.APIClient {
	return kfsdk.NewAPIClientWithAuth(newSDKMockAuthConfig(server))
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

// oauthRoleClaimAssocUnreachableAuthConfig points the SDK at an address
// nothing is listening on, so the HTTP client fails at the transport layer
// (connection refused) before any *http.Response is read. This reproduces
// the shape the generated SDK's callAPI/Execute methods return on a
// transport-level failure: (nil, err) — a nil *http.Response alongside a
// non-nil error.
type oauthRoleClaimAssocUnreachableAuthConfig struct{}

func (m *oauthRoleClaimAssocUnreachableAuthConfig) GetServerConfig() *auth_providers.Server {
	return &auth_providers.Server{
		Host:          "127.0.0.1:1",
		SkipTLSVerify: true,
	}
}

func (m *oauthRoleClaimAssocUnreachableAuthConfig) GetHttpClient() (*http.Client, error) {
	return &http.Client{Timeout: 5 * time.Second}, nil
}

func (m *oauthRoleClaimAssocUnreachableAuthConfig) Authenticate() error { return nil }

func newOAuthRoleClaimAssocUnreachableClient() *kfsdk.APIClient {
	return kfsdk.NewAPIClientWithAuth(&oauthRoleClaimAssocUnreachableAuthConfig{})
}

// TestUnitOAuthSecurityRoleClaimAssociation_CreateTransportErrorDoesNotPanic
// is the red/green regression test for the bug where Create() logs
// httpResp.StatusCode via tflog.Debug before checking `err != nil`. On a
// transport-level failure (DNS/connection-refused/TLS failure), the
// generated SDK's callAPI returns a nil *http.Response alongside the error,
// and Execute() passes that nil response straight through — dereferencing
// .StatusCode on it panics.
func TestUnitOAuthSecurityRoleClaimAssociation_CreateTransportErrorDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	const (
		roleId  int32 = 45
		claimId int32 = 9
	)

	sdkClient := newOAuthRoleClaimAssocUnreachableClient()

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

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Create panicked (nil httpResp transport-error regression): %v", rec)
			}
		}()
		r.Create(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected Create to fail with a diagnostic on a transport-level error, got no diagnostics")
	}
}

// TestUnitOAuthSecurityRoleClaimAssociation_DeleteTransportErrorDoesNotPanic
// is the Delete-path counterpart: Delete() dereferences httpReq.StatusCode
// (both in the tflog.Debug call and the `== 404` check) before checking
// `err != nil`, and panics identically on a nil httpReq.
func TestUnitOAuthSecurityRoleClaimAssociation_DeleteTransportErrorDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	const (
		roleId  int32 = 46
		claimId int32 = 10
	)

	sdkClient := newOAuthRoleClaimAssocUnreachableClient()

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
				t.Fatalf("Delete panicked (nil httpReq transport-error regression): %v", rec)
			}
		}()
		r.Delete(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected Delete to fail with a diagnostic on a transport-level error, got no diagnostics")
	}
}

// TestUnitOAuthSecurityRoleClaimAssociation_CreateClaimGetErrorDoesNotPanic is
// the red/green regression test for the fall-through bug in
// resourceOAuthSecurityRoleClaimAssociation.Create: when the security-claim
// GET (`/Security/Claims/{claimId}`) fails, the generated SDK Execute()
// returns a nil `*SecurityRoleClaimDefinitionsRoleClaimDefinitionResponse`
// alongside the error, but Create only called response.Diagnostics.AddError
// without returning — execution fell through and dereferenced
// `remoteClaimState.Provider`, panicking on the nil claim response. This
// mirrors the identical (already-fixed) pattern for the role GET a few lines
// above.
func TestUnitOAuthSecurityRoleClaimAssociation_CreateClaimGetErrorDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	const (
		roleId  int32 = 44
		claimId int32 = 8
	)

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Security/Roles/%d", roleId), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(nullFieldsRoleResponseBody(roleId)))
	})
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Security/Claims/%d", claimId), func(w http.ResponseWriter, r *http.Request) {
		// Simulate the claim GET failing. The generated SDK Execute() treats
		// any status >= 300 as an error and returns a nil claim response.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"Message":"internal error"}`))
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
	// claim GET fails, and must surface a diagnostic instead of silently
	// continuing.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Create panicked (claim-GET-error fall-through regression): %v", rec)
			}
		}()
		r.Create(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected Create to fail with a diagnostic when the claim GET errors, got no diagnostics")
	}

	found := false
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Summary(), "claim") || strings.Contains(d.Detail(), "claim") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a diagnostic mentioning the claim error, got: %+v", resp.Diagnostics)
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
