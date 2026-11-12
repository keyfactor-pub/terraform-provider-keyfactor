package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// for the SIGSEGV nil-pointer dereference in resourceCommandCertificate.Update
// that crashed `terraform apply` during an in-place update.
//
// Root cause: GetCertificateContext returns (nil, err) on failure, but the code
// only logged a warning via hasAPIErrors and then dereferenced
// certGetResp.ContentBytes (via parseLeafCert), panicking. The Read path was
// hardened with `certGetResp != nil` guards in v2.9.0; the fix aligns Update by
// returning at the hasAPIErrors branch.
//
// What this test exercises: the GET fails (HTTP 500), so GetCertificateContext
// returns (nil, err) and hasAPIErrors early-returns a clean diagnostic instead
// of the provider panicking at parseLeafCert(certGetResp.ContentBytes). On the
// UNFIXED code this panics (the deferred recover converts the panic into a test
// failure); on the fixed code Update returns with
// response.Diagnostics.HasError() == true and the diagnostic summary emitted by
// hasAPIErrors (ERR_SUMMARY_CERTIFICATE_RESOURCE_READ).
//
// Note: the second `certGetResp == nil` guard in Update is belt-and-suspenders
// for a (nil, nil) GET response. That is NOT reproducible through this httptest
// harness : every 200 yields a non-nil *GetCertificateResponse, and the only
// nil-data branch returns a non-nil error : so that guard (and its
// ERR_SUMMARY_CERTIFICATE_RESOURCE_UPDATE summary) is not directly exercised
// here.
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

	// Only the fields load-bearing before the hasAPIErrors early return are
	// populated: a CN (no CSR) so the CSR-vs-CN validation passes, the
	// ID/CertificateId used to build the GET args, CollectionId, and
	// ExpiryWarningDays. The null list/map element types are required for
	// Plan.Set / State.Set to succeed. Fields consumed only after the GET (key
	// password, SAN lists, metadata, owner role, revoke-on-destroy, certificate
	// format) are intentionally omitted : Update returns at hasAPIErrors before
	// they are read.
	nullList := types.List{ElemType: types.StringType, Null: true}
	nullMap := types.Map{ElemType: types.StringType, Null: true}

	plan := CommandCertificate{
		ID:                types.String{Value: "845070"},
		CertificateId:     types.Int64{Value: 845070},
		CommonName:        types.String{Value: "tf-unit-nil-update.example.com"},
		CSR:               types.String{Null: true},
		CollectionId:      types.Int64{Value: 0},
		ExpiryWarningDays: types.Int64{Null: true},
		DNSSANs:           nullList,
		IPSANs:            nullList,
		URISANs:           nullList,
		Metadata:          nullMap,
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

// ---- Class A/B: SAN diagnostics are reported and enrollment stops before issuing anything. ----

// illTypedSANs is a SAN list whose elements cannot be converted to strings.
func illTypedSANs() types.List {
	return types.List{ElemType: types.Int64Type, Elems: []attr.Value{types.Int64{Value: 1}}}
}

func goodSANs(vals ...string) types.List {
	elems := make([]attr.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, types.String{Value: v})
	}
	return types.List{ElemType: types.StringType, Elems: elems}
}

// parseSans used to overwrite its diagnostics on every call, so an error in dns_sans was dropped
// whenever ip_sans/uri_sans parsed fine.
func TestUnitParseSans_ReportsAnErrorFromAnyListNotOnlyTheLast(t *testing.T) {
	r := resourceCommandCertificate{}
	for name, plan := range map[string]CommandCertificate{
		"dns": {DNSSANs: illTypedSANs(), IPSANs: goodSANs("10.0.0.1"), URISANs: goodSANs("spiffe://x")},
		"ip":  {DNSSANs: goodSANs("a.example"), IPSANs: illTypedSANs(), URISANs: goodSANs("spiffe://x")},
		"uri": {DNSSANs: goodSANs("a.example"), IPSANs: goodSANs("10.0.0.1"), URISANs: illTypedSANs()},
	} {
		plan := plan
		t.Run(name, func(t *testing.T) {
			_, _, _, diags := r.parseSans(context.Background(), &plan)
			assert.True(t, diags.HasError(), "the %s_sans conversion error must not be dropped", name)
		})
	}

	_, _, _, diags := r.parseSans(context.Background(), &CommandCertificate{
		DNSSANs: goodSANs("a.example"), IPSANs: goodSANs("10.0.0.1"), URISANs: types.List{Null: true, ElemType: types.StringType},
	})
	assert.False(t, diags.HasError(), "well-typed and null lists are fine: %v", diags)
}

// enrollPFXV2 / enrollCSR must stop at a SAN error instead of enrolling with the SANs missing.
// (The provider here has no client, so carrying on would panic.)
func TestUnitEnroll_UnreadableSANsStopBeforeEnrolling(t *testing.T) {
	ctx := context.Background()
	r := resourceCommandCertificate{}

	t.Run("pfx", func(t *testing.T) {
		plan := &CommandCertificate{
			CommonName: types.String{Value: "cn.example"}, DNSSANs: illTypedSANs(),
			IPSANs: goodSANs(), URISANs: goodSANs(), CertificateFormat: types.String{Value: "PFX"},
			Metadata: types.Map{Null: true, ElemType: types.StringType},
		}
		var res *CommandCertificate
		var diags diag.Diagnostics
		require.NotPanics(t, func() { res, diags = r.enrollPFXV2(ctx, plan) })
		assert.Nil(t, res)
		require.True(t, diags.HasError())
		assert.Contains(t, diags.Errors()[0].Detail(), "can't unmarshal", "the SAN conversion error itself must be what stops enrollment")
	})
	t.Run("csr", func(t *testing.T) {
		plan := &CommandCertificate{
			DNSSANs: illTypedSANs(), IPSANs: goodSANs(), URISANs: goodSANs(), CertificateFormat: types.String{Value: "PEM"},
			Metadata: types.Map{Null: true, ElemType: types.StringType},
		}
		var res *CommandCertificate
		var diags diag.Diagnostics
		require.NotPanics(t, func() {
			res, diags = r.enrollCSR(ctx, "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----", plan)
		})
		assert.Nil(t, res)
		require.True(t, diags.HasError())
		assert.Contains(t, diags.Errors()[0].Detail(), "can't unmarshal", "the SAN conversion error itself must be what stops enrollment")
	})
}
