package keyfactor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: query normalization — "provider produced inconsistent
// result after apply" on keyfactor_certificate_collection Create and Update.
//
// Keyfactor Command normalizes query strings by inserting spaces inside
// parentheses: a user writes `(OwnerRoleName -eq "X")` but the server
// echoes back `( OwnerRoleName -eq "X" )`. Before this fix, Create() and
// Update() called collectionResponseToState(resp) and stored the
// server-normalized query directly in state. The Plugin Framework then
// compared that against the plan value (user's original spelling) and
// raised "provider produced inconsistent result after apply".
//
// Read() already preserves state.Query from prior state (GetById has no
// Query field at all). Create() and Update() now likewise preserve the
// plan value, since the user's original query is the authoritative spelling
// from Terraform's perspective.
//
// Test shape: each test drives the resource method against a local httptest
// server that returns a server-normalized query in the response body. The
// test asserts (a) no diagnostics error and (b) the resulting state.Query
// equals the plan value, not the server-normalized form.
// ---------------------------------------------------------------------------

const (
	// userQuery is the query exactly as the user writes it in HCL.
	userQuery = `(OwnerRoleName -eq "X" OR OwnerRoleName -eq "Y")`
	// serverNormalizedQuery is what Command echoes back after normalization.
	serverNormalizedQuery = `( OwnerRoleName -eq "X" OR OwnerRoleName -eq "Y" )`
)

// newCollectionCreateNormalizationServer returns an httptest TLS server that
// handles POST /CertificateCollections by returning a
// CertificateCollectionsCertificateCollectionResponse with the
// server-normalized query (spaces inside parens), simulating Command's
// normalization behaviour.
func newCollectionCreateNormalizationServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := v1.CertificateCollectionsCertificateCollectionResponse{}
		resp.SetId(42)
		resp.SetName("Test Collection_TF")
		resp.SetQuery(serverNormalizedQuery)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("newCollectionCreateNormalizationServer: failed to encode response: %v", err)
		}
	}))
}

// newCollectionUpdateNormalizationServer returns an httptest TLS server that
// handles:
//
//   - GET /CertificateCollections/{id} — returns a
//     CSSCMSDataModelModelsCertificateQuery (the pre-update GET used by the
//     read-modify-write pattern in Update()).
//   - PUT /CertificateCollections — returns a
//     CertificateCollectionsCertificateCollectionResponse with the
//     server-normalized query.
func newCollectionUpdateNormalizationServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			// Pre-update GET: CSSCMSDataModelModelsCertificateQuery has no Query field.
			getResp := v1.CSSCMSDataModelModelsCertificateQuery{}
			getResp.SetId(42)
			getResp.SetName("Test Collection_TF")
			if err := json.NewEncoder(w).Encode(getResp); err != nil {
				t.Fatalf("newCollectionUpdateNormalizationServer GET: failed to encode response: %v", err)
			}
		case http.MethodPut:
			// Update response: returns normalized query.
			putResp := v1.CertificateCollectionsCertificateCollectionResponse{}
			putResp.SetId(42)
			putResp.SetName("Test Collection_TF")
			putResp.SetQuery(serverNormalizedQuery)
			if err := json.NewEncoder(w).Encode(putResp); err != nil {
				t.Fatalf("newCollectionUpdateNormalizationServer PUT: failed to encode response: %v", err)
			}
		default:
			t.Fatalf("newCollectionUpdateNormalizationServer: unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitCertificateCollectionCreatePreservesQueryNormalization verifies that
// Create() stores the plan's original query value in state even when the
// server echoes back a differently-spaced (normalized) form. Without the fix,
// collectionResponseToState(resp) would write serverNormalizedQuery into state
// and the Plugin Framework would raise "provider produced inconsistent result
// after apply".
func TestUnitCertificateCollectionCreatePreservesQueryNormalization(t *testing.T) {
	ctx := context.Background()

	server := newCollectionCreateNormalizationServer(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := certificateCollectionSchemaForTest(t, ctx)

	plan := KeyfactorCertificateCollectionState{
		Name:  types.String{Value: "Test Collection_TF"},
		Query: types.String{Value: userQuery},
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.CreateResourceRequest{Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var resultState KeyfactorCertificateCollectionState
	if d := resp.State.Get(ctx, &resultState); d.HasError() {
		t.Fatalf("resp.State.Get returned diagnostics: %+v", d)
	}

	if resultState.Query.Value != userQuery {
		t.Errorf(
			"Create stored server-normalized query in state (inconsistent-result-after-apply bug):\n  got:  %q\n  want: %q",
			resultState.Query.Value, userQuery,
		)
	}
}

// TestUnitCertificateCollectionUpdatePreservesQueryNormalization verifies that
// Update() stores the plan's original query value in state even when the
// server echoes back a normalized form. Without the fix, the conditional
// null-check fallback only fired when the server omitted Query entirely; a
// present-but-normalized value passed straight through to state unchanged.
func TestUnitCertificateCollectionUpdatePreservesQueryNormalization(t *testing.T) {
	ctx := context.Background()

	server := newCollectionUpdateNormalizationServer(t)
	defer server.Close()
	sdkClient := newTemplateUpdateSDKClient(server)

	schema := certificateCollectionSchemaForTest(t, ctx)

	state := KeyfactorCertificateCollectionState{
		ID:    types.Int64{Value: 42},
		Name:  types.String{Value: "Test Collection_TF"},
		Query: types.String{Value: userQuery},
	}
	plan := state // plan keeps the same user query

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: stateObj.Set returned diagnostics: %+v", d)
	}
	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: planObj.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: planObj.Raw}

	r := resourceCertificateCollection{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned unexpected diagnostics: %+v", resp.Diagnostics)
	}

	var resultState KeyfactorCertificateCollectionState
	if d := resp.State.Get(ctx, &resultState); d.HasError() {
		t.Fatalf("resp.State.Get returned diagnostics: %+v", d)
	}

	if resultState.Query.Value != userQuery {
		t.Errorf(
			"Update stored server-normalized query in state (inconsistent-result-after-apply bug):\n  got:  %q\n  want: %q",
			resultState.Query.Value, userQuery,
		)
	}
}
