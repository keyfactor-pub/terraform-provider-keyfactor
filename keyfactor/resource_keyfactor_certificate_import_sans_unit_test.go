package keyfactor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth_providers "github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	api "github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	pkcs12 "github.com/spbsoluble/go-pkcs12"
)

// ---------------------------------------------------------------------------
// Regression tests: keyfactor_certificate's dns_sans is
// never populated on import, forcing a full replace (cascading into
// dependent keyfactor_certificate_deployment resources) on the very next
// plan.
//
// Live repro: a PFX-enrolled
// certificate whose original config never declared dns_sans, but whose
// actual issued certificate has a DNS SAN (many CAs/templates auto-copy the
// CommonName into the SAN list at issuance), came back from
// `terraform import` with dns_sans = null even though the real certificate
// has a real SAN. dns_sans is Optional (not Computed) with
// tfsdk.RequiresReplace(), so that null-vs-non-null delta forces a full
// destroy+recreate the moment a matching dns_sans is declared in config
// (exactly what a corrected import's config should do), and even forces
// replacement immediately if the ORIGINAL create-time state already had a
// non-null value that a stale local config doesn't repeat.
//
// This test drives resourceCommandCertificate.ImportState directly against a
// local mock Command server (GET Certificates/{id} + POST
// Certificates/Recover, matching the PFX-with-server-side-key path used by
// TestLeafSelectionPFX in download_leaf_test.go) to determine, empirically,
// whether the current import path actually reconstructs the certificate's
// real DNS SAN or silently drops it.
// ---------------------------------------------------------------------------

// restorePFXPasswordFormatGlobals sets the package-level PFX password-format
// vars (normally populated by provider.Configure) to their documented
// defaults for the duration of the test, restoring whatever was there before
// on cleanup. ImportState generates a one-time recovery password via these
// vars; left at their Go zero value (as they are when a provider{} is
// constructed directly, bypassing Configure, like these tests do) that
// produces an empty password, which client.RecoverCertificate rejects
// outright ("password required to recover private key with certificate") --
// a test-harness artifact unrelated to the dns_sans behavior under test.
func restorePFXPasswordFormatGlobals(t *testing.T) {
	t.Helper()
	oldLen, oldSpecial, oldNum, oldUpper := PFXPasswordLength, PFXPasswordSpecialChars, PFXPasswordDigits, PFXPasswordUpperCases
	PFXPasswordLength = DEFAULT_PFX_PASSWORD_LEN
	PFXPasswordSpecialChars = DEFAULT_PFX_PASSWORD_SPECIAL_CHAR_COUNT
	PFXPasswordDigits = DEFAULT_PFX_PASSWORD_NUMBER_COUNT
	PFXPasswordUpperCases = DEFAULT_PFX_PASSWORD_UPPER_COUNT
	t.Cleanup(func() {
		PFXPasswordLength, PFXPasswordSpecialChars, PFXPasswordDigits, PFXPasswordUpperCases = oldLen, oldSpecial, oldNum, oldUpper
	})
}

// buildSANLeaf creates a root CA, intermediate CA, and a leaf cert (signed by
// the intermediate) whose Subject Alternative Names include dnsNames. This
// mirrors download_leaf_test.go's buildChain, but additionally stamps DNS
// SANs onto the leaf -- buildChain's leaf has none, which isn't suitable for
// this SAN round-trip test.
func buildSANLeaf(t *testing.T, dnsNames ...string) (root, intermediate, leaf *x509.Certificate, leafKey *rsa.PrivateKey) {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	root, _ = x509.ParseCertificate(rootDER)

	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, root, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate cert: %v", err)
	}
	intermediate, _ = x509.ParseCertificate(intDER)

	leafKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	cn := "no-cn"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermediate, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, _ = x509.ParseCertificate(leafDER)
	return
}

// newImportSANsMockServer returns an httptest server standing in for Command,
// routing:
//   - GET  Certificates/{id}      -> certGetResp (HasPrivateKey=true, PFX path)
//   - POST Certificates/Recover   -> {"PFX": base64(pfxDER)} (format=PFX: the
//     wire format ImportState requests, matching client.RecoverCertificate's
//     "PFX"/"pfx" branch which passes the blob through undecoded -- decoding
//     happens client-side in recoverPrivateKeyFromKeyfactorCommand via
//     api.UnpackPkcs12)
func newImportSANsMockServer(
	t *testing.T, certGetResp api.GetCertificateResponse, pfxDER []byte, chainCerts ...*x509.Certificate,
) *httptest.Server {
	t.Helper()
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)
	recoverBody, err := json.Marshal(map[string]string{"PFX": pfxB64, "FileName": "cert.pfx"})
	if err != nil {
		t.Fatalf("marshal recover body: %v", err)
	}
	getBody, err := json.Marshal(certGetResp)
	if err != nil {
		t.Fatalf("marshal certGetResp: %v", err)
	}
	// ImportState falls back to Certificates/Download (P7B) whenever the PFX
	// recovery unpack didn't yield a chain -- always answer it so that path,
	// if hit, doesn't fail the test for an unrelated reason.
	downloadBody, err := json.Marshal(map[string]string{"Content": buildRootFirstP7B(t, chainCerts...)})
	if err != nil {
		t.Fatalf("marshal download body: %v", err)
	}

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "Recover"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(recoverBody)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "Download"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(downloadBody)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "Certificates"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(getBody)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
}

// newImportSANsMockClient builds an api.Client wired to srv (mirrors
// download_leaf_test.go's newMockClient).
func newImportSANsMockClient(t *testing.T, srv *httptest.Server) *api.Client {
	t.Helper()
	tlsClient := srv.Client()
	tlsClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	auth := &mockLeafAuth{
		client: tlsClient,
		server: &auth_providers.Server{
			Host:          srv.URL,
			APIPath:       "KeyfactorAPI",
			SkipTLSVerify: true,
		},
	}
	ctx := context.Background()
	return api.NewKeyfactorClientWithAuth(auth, &ctx)
}

// TestUnitCertificateImportPopulatesDNSSANs is the direct regression test:
// ImportState for a PFX-enrolled certificate whose actual issued
// certificate has a DNS SAN (e.g. auto-copied from the CommonName by the CA)
// must populate dns_sans from that real certificate content, not leave it
// null.
func TestUnitCertificateImportPopulatesDNSSANs(t *testing.T) {
	restorePFXPasswordFormatGlobals(t)

	const cn = "tf-release-pfx-TF.example.com"
	root, intermediate, leaf, leafKey := buildSANLeaf(t, cn)

	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, []*x509.Certificate{intermediate, root}, "otp-password")
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}

	certGetResp := api.GetCertificateResponse{
		Id:                       201,
		Thumbprint:               "AABBCC",
		SerialNumber:             leaf.SerialNumber.String(),
		IssuedDN:                 leaf.Subject.String(),
		IssuedCN:                 cn,
		HasPrivateKey:            true,
		ContentBytes:             base64.StdEncoding.EncodeToString(leaf.Raw),
		CertificateAuthorityName: "CA1\\\\IssuingCA",
		KeyAlgorithm:             "RSA",
		KeySizeInBits:            2048,
	}

	srv := newImportSANsMockServer(t, certGetResp, pfxDER, intermediate, root)
	defer srv.Close()

	client := newImportSANsMockClient(t, srv)

	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	schema, diags := resourceCommandCertificateType{}.GetSchema(context.Background())
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	req := tfsdk.ImportResourceStateRequest{ID: "201"}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState returned diagnostics: %+v", resp.Diagnostics)
	}

	var result CommandCertificate
	if d := resp.State.Get(context.Background(), &result); d.HasError() {
		t.Fatalf("failed to read back imported state: %+v", d)
	}

	if result.DNSSANs.Null {
		t.Fatalf(
			"dns_sans is null after import -- this reproduces the bug: a certificate whose real content "+
				"has DNS SAN %q came back from ImportState with dns_sans unset, which forces replacement "+
				"(cascading into dependent keyfactor_certificate_deployment resources) the moment a config "+
				"declares the correct value or the resource already had one from its original create-time state.",
			cn,
		)
	}
	if len(result.DNSSANs.Elems) != 1 {
		t.Fatalf("dns_sans on import = %v, want exactly [%q]", result.DNSSANs.Elems, cn)
	}
	elem, ok := result.DNSSANs.Elems[0].(types.String)
	if !ok || elem.Value != cn {
		t.Errorf("dns_sans[0] on import = %v, want %q", result.DNSSANs.Elems[0], cn)
	}
}

// TestUnitCertificateImportCNOnlyLeavesDNSSANsNull is the negative-space
// companion: a certificate with NO DNS SAN at all (a true CN-only
// enrollment) must still come back from ImportState with dns_sans null --
// the fix must not start inventing SANs that were never on the
// certificate, preserving the existing declared-vs-undeclared contract.
func TestUnitCertificateImportCNOnlyLeavesDNSSANsNull(t *testing.T) {
	restorePFXPasswordFormatGlobals(t)

	const cn = "tf-cn-only.example.com"
	root, intermediate, leaf, leafKey := buildSANLeaf(t) // no DNS SANs
	leaf.Subject.CommonName = cn

	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, []*x509.Certificate{intermediate, root}, "otp-password")
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}

	certGetResp := api.GetCertificateResponse{
		Id:            202,
		HasPrivateKey: true,
		ContentBytes:  base64.StdEncoding.EncodeToString(leaf.Raw),
		KeyAlgorithm:  "RSA",
		KeySizeInBits: 2048,
	}

	srv := newImportSANsMockServer(t, certGetResp, pfxDER, intermediate, root)
	defer srv.Close()

	client := newImportSANsMockClient(t, srv)

	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	schema, diags := resourceCommandCertificateType{}.GetSchema(context.Background())
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	req := tfsdk.ImportResourceStateRequest{ID: "202"}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState returned diagnostics: %+v", resp.Diagnostics)
	}

	var result CommandCertificate
	if d := resp.State.Get(context.Background(), &result); d.HasError() {
		t.Fatalf("failed to read back imported state: %+v", d)
	}

	if !result.DNSSANs.Null {
		t.Errorf("dns_sans on import = %v, want null for a true CN-only certificate with no SANs", result.DNSSANs.Elems)
	}
}

// TestUnitCertificateSANsAreComputed is the schema-level regression test for
// the plan-stability half of the same bug: dns_sans/ip_sans/uri_sans must be
// Computed (in addition to Optional) with a UseStateForUnknown-style plan
// modifier so that an import-populated real value survives an undeclared
// config on the next plan, instead of the framework treating "declared:
// null" as "changing to null" and triggering RequiresReplace. Before the
// fix these attributes were Optional only -- exactly the "certificate_
// authority" pattern already used elsewhere in this same schema (Optional +
// Computed + UseStateForUnknown + RequiresReplace) for the same reason.
func TestUnitCertificateSANsAreComputed(t *testing.T) {
	schema, diags := resourceCommandCertificateType{}.GetSchema(context.Background())
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	for _, name := range []string{"dns_sans", "ip_sans", "uri_sans"} {
		attr, ok := schema.Attributes[name]
		if !ok {
			t.Fatalf("schema has no %s attribute", name)
		}
		if !attr.Optional {
			t.Errorf("%s: expected Optional=true", name)
		}
		if !attr.Computed {
			t.Errorf(
				"%s: expected Computed=true, got false -- without Computed, an undeclared %s plans to Null "+
					"even when prior state (e.g. from a terraform import) has a real value, and because %s "+
					"has RequiresReplace, that null-vs-non-null delta forces a full destroy+recreate",
				name, name, name,
			)
		}
		if len(attr.PlanModifiers) < 2 {
			t.Errorf(
				"%s: expected at least 2 plan modifiers (UseStateForUnknown + RequiresReplace), got %d",
				name, len(attr.PlanModifiers),
			)
		}
	}
}

// TestUnitKnownListFromPlanCollapsesUnknownToNull is a focused unit test for
// the helper that keeps Create()'s final state valid now that dns_sans/
// ip_sans/uri_sans are Computed: a brand-new resource whose config doesn't
// declare one of these attributes plans it Unknown (Computed, no prior
// state for UseStateForUnknown to carry forward), and the framework rejects
// a final Create() state that still contains an Unknown value.
func TestUnitKnownListFromPlanCollapsesUnknownToNull(t *testing.T) {
	unknown := types.List{Unknown: true, ElemType: types.StringType}
	got := knownListFromPlan(unknown)
	if !got.Null || got.Unknown {
		t.Errorf("knownListFromPlan(Unknown) = %+v, want a null (not unknown) list", got)
	}
	if got.ElemType != types.StringType {
		t.Errorf("knownListFromPlan(Unknown) ElemType = %v, want types.StringType preserved", got.ElemType)
	}

	known := stringSliceToTfList([]string{"a.example.com"})
	if got := knownListFromPlan(known); !got.Equal(known) {
		t.Errorf("knownListFromPlan(known) = %+v, want unchanged %+v", got, known)
	}
}
