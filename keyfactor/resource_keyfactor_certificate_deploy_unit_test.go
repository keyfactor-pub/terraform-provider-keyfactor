package keyfactor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// certDeployMockAuthConfig implements api.AuthConfig for httptest-backed unit
// tests of the certificate deployment resource.
type certDeployMockAuthConfig struct {
	server *httptest.Server
}

func (m *certDeployMockAuthConfig) GetServerConfig() *auth_providers.Server {
	return &auth_providers.Server{
		Host:          m.server.URL,
		APIPath:       "KeyfactorAPI",
		SkipTLSVerify: true,
	}
}

func (m *certDeployMockAuthConfig) GetHttpClient() (*http.Client, error) {
	return m.server.Client(), nil
}

func (m *certDeployMockAuthConfig) Authenticate() error       { return nil }
func (m *certDeployMockAuthConfig) GetCommandVersion() string { return "25.1.0.0" }

func newCertDeployMockClient(server *httptest.Server) *api.Client {
	return &api.Client{
		AuthClient: &certDeployMockAuthConfig{server: server},
	}
}

// certDeployPanicMux builds the httptest handler shared by the Create and
// Update regression tests below: GetCertificateContext (GET
// Certificates/{id}) fails with a 500, so kfClient.GetCertificateContext
// returns (nil, err); GetCertStoreInventory (GET
// CertificateStores/{storeId}/Inventory) returns one inventory entry whose
// Name matches certAlias and which has at least one inventoried certificate,
// so validateDeployment's `iCert.Id == certObj.Id` comparison is reached with
// certObj == nil.
func certDeployPanicMux(certificateID int, storeId, certAlias string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Certificates/%d", certificateID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"Message":"simulated server error"}`))
	})

	invPath := fmt.Sprintf("/KeyfactorAPI/CertificateStores/%s/Inventory", storeId)
	var inventoryHits int
	mux.HandleFunc(invPath, func(w http.ResponseWriter, r *http.Request) {
		inventoryHits++
		w.WriteHeader(http.StatusOK)
		if inventoryHits == 1 {
			// First page: one inventory entry whose alias matches, with at
			// least one certificate so validateDeployment's inner loop body
			// executes and dereferences certObj.Id.
			_, _ = w.Write([]byte(fmt.Sprintf(
				`[{"Name":%q,"Certificates":[{"Id":123}]}]`,
				certAlias,
			)))
			return
		}
		// Subsequent pages: empty, so GetCertStoreInventory's pagination loop
		// terminates.
		_, _ = w.Write([]byte(`[]`))
	})

	return mux
}

// TestUnitKeyfactorCertificateDeployResource_CreateNilCertificateDataDoesNotPanic
// is the red/green regression test for the nil-pointer dereference in
// resourceCommandCertificateDeployment.Create: when GetCertificateContext
// fails, the code adds a diagnostic error but does not return, falling
// through into validateDeployment with a nil certificateData. If the store's
// inventory has any entry whose alias matches and has at least one
// certificate, validateDeployment dereferences certObj.Id on a nil pointer
// and panics.
func TestUnitKeyfactorCertificateDeployResource_CreateNilCertificateDataDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	const (
		certificateID = 500
		storeId       = "store-1"
		certAlias     = "myalias"
	)

	server := httptest.NewTLSServer(certDeployPanicMux(certificateID, storeId, certAlias))
	defer server.Close()

	client := newCertDeployMockClient(server)

	schema, sDiags := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	nullMap := types.Map{ElemType: types.StringType, Null: true}
	plan := CommandCertificateDeployment{
		ID:               types.String{Unknown: true},
		CertificateId:    types.Int64{Value: certificateID},
		StoreId:          types.String{Value: storeId},
		CertificateAlias: types.String{Value: certAlias},
		KeyPassword:      types.String{Null: true},
		JobParameters:    nullMap,
		Overwrite:        types.Bool{Value: false},
		Redeploy:         types.Bool{Value: false},
		SkipRemoval:      types.Bool{Value: false},
	}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	r := resourceCommandCertificateDeployment{p: provider{configured: true, client: client}}

	req := tfsdk.CreateResourceRequest{Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	// The whole point of this regression test: Create must NOT panic when
	// GetCertificateContext fails. Convert any panic into a clear test
	// failure so the unfixed code is observably red.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Create panicked (nil-deref regression): %v", rec)
			}
		}()
		r.Create(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected Create to surface a diagnostic error when the certificate GET fails, got none")
	}
}

// TestUnitKeyfactorCertificateDeployResource_UpdateNilCertificateDataDoesNotPanic
// is the Update-path counterpart of the Create regression test above: the
// same fall-through bug exists in resourceCommandCertificateDeployment.Update.
func TestUnitKeyfactorCertificateDeployResource_UpdateNilCertificateDataDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	const (
		certificateID = 501
		storeId       = "store-2"
		certAlias     = "myalias2"
	)

	server := httptest.NewTLSServer(certDeployPanicMux(certificateID, storeId, certAlias))
	defer server.Close()

	client := newCertDeployMockClient(server)

	schema, sDiags := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	nullMap := types.Map{ElemType: types.StringType, Null: true}
	plan := CommandCertificateDeployment{
		ID:               types.String{Value: "existing-id"},
		CertificateId:    types.Int64{Value: certificateID},
		StoreId:          types.String{Value: storeId},
		CertificateAlias: types.String{Value: certAlias},
		KeyPassword:      types.String{Null: true},
		JobParameters:    nullMap,
		Overwrite:        types.Bool{Value: false},
		Redeploy:         types.Bool{Value: false},
		SkipRemoval:      types.Bool{Value: false},
	}
	state := plan

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCommandCertificateDeployment{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Update panicked (nil-deref regression): %v", rec)
			}
		}()
		r.Update(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected Update to surface a diagnostic error when the certificate GET fails, got none")
	}
}
