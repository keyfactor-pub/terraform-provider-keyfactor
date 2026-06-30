package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// certUpdateMockAuthConfig implements api.AuthConfig for httptest-backed unit
// tests of the certificate resource Update path.
type certUpdateMockAuthConfig struct {
	server *httptest.Server
}

func (m *certUpdateMockAuthConfig) GetServerConfig() *auth_providers.Server {
	return &auth_providers.Server{
		Host:          m.server.URL,
		APIPath:       "KeyfactorAPI",
		SkipTLSVerify: true,
	}
}

func (m *certUpdateMockAuthConfig) GetHttpClient() (*http.Client, error) {
	return m.server.Client(), nil
}

func (m *certUpdateMockAuthConfig) Authenticate() error       { return nil }
func (m *certUpdateMockAuthConfig) GetCommandVersion() string { return "25.1.0.0" }

func newCertUpdateMockClient(server *httptest.Server) *api.Client {
	return &api.Client{
		AuthClient: &certUpdateMockAuthConfig{server: server},
	}
}

// TestUnitKeyfactorCertificateResource_UpdateNilGetResponse is a regression test
// for the SIGSEGV nil-pointer dereference at
// resource_keyfactor_certificate.go:1487 that crashed `terraform apply` during
// an in-place update (e.g. flipping certificate_format to "PFX").
//
// Root cause: in resourceCommandCertificate.Update, GetCertificateContext
// returns (nil, err) on failure, but the code only logged a warning via
// hasAPIErrors and then dereferenced certGetResp.ContentBytes, panicking. The
// Read path was hardened with `certGetResp != nil` guards in v2.9.0; this test
// verifies Update now surfaces a clean diagnostic error and returns instead of
// panicking.
//
// The test drives Update directly against an httptest server whose
// GET /KeyfactorAPI/Certificates/... endpoint returns HTTP 500, forcing
// GetCertificateContext to return (nil, err). On the UNFIXED code this panics
// (the deferred recover converts the panic into a test failure); on the fixed
// code Update returns with response.Diagnostics.HasError() == true.
func TestUnitKeyfactorCertificateResource_UpdateNilGetResponse(t *testing.T) {
	ctx := context.Background()

	// httptest server: every request under /KeyfactorAPI/Certificates returns
	// HTTP 500 so GetCertificateContext returns (nil, err).
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"Message":"simulated server error"}`))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	// Build the resource schema so we can populate Plan and State.
	schema, sDiags := resourceCommandCertificateType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	// Minimal CommandCertificate sufficient to reach the GetCertificateContext
	// call: a CN (no CSR) so the CSR-vs-CN validation passes, an ID/cert ID, a
	// template/CA, and certificate_format flipping from PEM -> PFX (the real
	// crash scenario). types.List/types.Map fields must carry an ElemType.
	nullList := types.List{ElemType: types.StringType, Null: true}
	nullMap := types.Map{ElemType: types.StringType, Null: true}

	plan := CommandCertificate{
		ID:                   types.String{Value: "845070"},
		CertificateId:        types.Int64{Value: 845070},
		CommonName:           types.String{Value: "tf-unit-nil-update.example.com"},
		CSR:                  types.String{Null: true},
		CertificateTemplate:  types.String{Value: "TestTemplate"},
		CertificateAuthority: types.String{Value: "TestCA"},
		EnrollmentPattern:    types.String{Null: true},
		CollectionId:         types.Int64{Value: 0},
		KeyPassword:          types.String{Value: "Tftest123456"},
		CertificateFormat:    types.String{Value: "PFX"},
		DNSSANs:              nullList,
		IPSANs:               nullList,
		URISANs:              nullList,
		Metadata:             nullMap,
		OwnerRoleName:        types.String{Null: true},
		RevokeOnDestroy:      types.Bool{Value: false},
		ExpiryWarningDays:    types.Int64{Null: true},
	}

	// State mirrors plan but with the old format (PEM) so the format-change
	// branch is what would normally execute after the GET.
	state := plan
	state.CertificateFormat = types.String{Value: "PEM"}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCommandCertificate{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	// The whole point of this regression test: Update must NOT panic when
	// GetCertificateContext returns (nil, err). Convert any panic into a clear
	// test failure so the unfixed code is observably red.
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

	// Sanity: the diagnostic should mention the certificate read failure, not a
	// generic panic message.
	var found bool
	for _, d := range resp.Diagnostics.Errors() {
		if d.Summary() == ERR_SUMMARY_CERTIFICATE_RESOURCE_READ {
			found = true
			break
		}
	}
	if !found {
		t.Logf("diagnostics: %+v", resp.Diagnostics)
		t.Fatalf("expected a %q error diagnostic", ERR_SUMMARY_CERTIFICATE_RESOURCE_READ)
	}
}
