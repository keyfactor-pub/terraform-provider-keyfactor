package keyfactor

// TestDownloadCertificateLeafSelection is a mock-server test that verifies the
// provider's Read path correctly returns the end-entity (leaf) certificate when
// the Certificates/Download endpoint returns a root-first P7B.
//
// This is the provider-level regression test for the P7B chain-ordering bug
// (reported against v2.7.1). It does NOT require a live Keyfactor lab or VCR
// cassettes — the mock HTTPS server is built entirely from Go crypto.
//
// Run with:
//
//	go test -run TestDownloadCertificateLeafSelection -v ./keyfactor/...

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	api "github.com/Keyfactor/keyfactor-go-client/v3/api"
	auth_providers "github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"go.mozilla.org/pkcs7"
)

// mockLeafAuth implements api.AuthConfig backed by a custom *http.Client.
type mockLeafAuth struct {
	client *http.Client
	server *auth_providers.Server
}

func (m *mockLeafAuth) Authenticate() error                        { return nil }
func (m *mockLeafAuth) GetHttpClient() (*http.Client, error)       { return m.client, nil }
func (m *mockLeafAuth) GetServerConfig() *auth_providers.Server    { return m.server }

func TestDownloadCertificateLeafSelection(t *testing.T) {
	// --- Build a CA cert and a leaf cert from scratch ---
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	const leafCN = "hotfix-test-leaf.example.com"
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: leafCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// --- Build a ROOT-FIRST P7B (CA before leaf — the bug trigger) ---
	sd, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		t.Fatalf("pkcs7.NewSignedData: %v", err)
	}
	sd.AddCertificate(caCert)   // ROOT FIRST
	sd.AddCertificate(leafCert) // leaf second
	p7DER, err := sd.Finish()
	if err != nil {
		t.Fatalf("pkcs7.Finish: %v", err)
	}
	p7B64 := base64.StdEncoding.EncodeToString(p7DER)

	// --- Mock HTTPS server: responds to any request with the P7B JSON ---
	downloadBody, _ := json.Marshal(map[string]string{"Content": p7B64})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(downloadBody)
	}))
	defer srv.Close()

	// --- Wire up an api.Client pointing at the mock server ---
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
	client := api.NewKeyfactorClientWithAuth(auth, &ctx)

	// --- Call the provider helper under test ---
	leafPEM, _, _, diags := downloadCertificateFromKeyfactorCommand(ctx, 1, 0, client)
	if diags.HasError() {
		t.Fatalf("downloadCertificateFromKeyfactorCommand returned error diags: %v", diags)
	}
	if leafPEM == "" {
		t.Fatal("downloadCertificateFromKeyfactorCommand returned empty leafPEM")
	}

	// --- Parse the returned PEM and assert it is the end-entity leaf ---
	block, _ := pem.Decode([]byte(leafPEM))
	if block == nil {
		t.Fatal("returned leafPEM is not a valid PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse returned certificate: %v", err)
	}

	if cert.IsCA {
		t.Errorf("BUG: downloadCertificateFromKeyfactorCommand returned CA cert (CN=%q IsCA=true) instead of leaf — P7B chain ordering fix is not working", cert.Subject.CommonName)
	}
	if cert.Subject.CommonName != leafCN {
		t.Errorf("returned cert CN = %q, want %q", cert.Subject.CommonName, leafCN)
	}
	_ = leafCert // suppress unused warning
	t.Logf("PASS: returned leaf CN=%q IsCA=%v", cert.Subject.CommonName, cert.IsCA)
}
