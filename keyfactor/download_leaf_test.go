package keyfactor

// Regression tests for the P7B/PFX chain-ordering bug (reported against v2.7.1).
// When Certificates/Download returns a root-first P7B, or Certificates/Recover
// returns a PFX with certs ordered CA-before-leaf, the provider was returning the
// root CA as the leaf : causing forced replacement on every terraform plan.
//
// Fixed in:
//   - keyfactor-go-client v3.5.2+: findLeafCert() (P7B path)
//   - go-pkcs12 v0.4.0: localKeyID matching in DecodeChain (PFX path)
//
// Tests here use in-process mock HTTPS servers and Go crypto : no lab required.
//
// Run with:
//
//	go test -run TestLeafSelection -v ./keyfactor/...

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
	"strings"
	"testing"
	"time"

	auth_providers "github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	api "github.com/Keyfactor/keyfactor-go-client/v3/api"
	pkcs12 "github.com/spbsoluble/go-pkcs12"
	"go.mozilla.org/pkcs7"
)

// mockLeafAuth implements api.AuthConfig backed by a custom *http.Client.
type mockLeafAuth struct {
	client *http.Client
	server *auth_providers.Server
}

func (m *mockLeafAuth) Authenticate() error                     { return nil }
func (m *mockLeafAuth) GetHttpClient() (*http.Client, error)    { return m.client, nil }
func (m *mockLeafAuth) GetServerConfig() *auth_providers.Server { return m.server }
func (m *mockLeafAuth) GetCommandVersion() string               { return "25.1.0.0" }

// buildChain creates a root CA, optional intermediate CA, and a leaf cert signed
// by the nearest parent. Returns (rootCert, intermediateCert, leafCert, leafKey).
// When withIntermediate is false, intermediateCert is nil and leaf is signed by root.
func buildChain(t *testing.T, withIntermediate bool) (root, intermediate, leaf *x509.Certificate, leafKey *rsa.PrivateKey) {
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

	parentCert := root
	parentKey := rootKey

	if withIntermediate {
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
		parentCert = intermediate
		parentKey = intKey
	}

	leafKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, parentCert, &leafKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, _ = x509.ParseCertificate(leafDER)
	return
}

// buildRootFirstP7B encodes certs into a P7B with root-first ordering.
func buildRootFirstP7B(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	sd, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		t.Fatalf("pkcs7.NewSignedData: %v", err)
	}
	for _, c := range certs {
		sd.AddCertificate(c)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatalf("pkcs7.Finish: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// newMockClient builds an api.Client wired to srv.
func newMockClient(t *testing.T, srv *httptest.Server) *api.Client {
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

// assertLeaf parses leafPEM and asserts it is the end-entity cert (not a CA).
func assertLeaf(t *testing.T, leafPEM string) {
	t.Helper()
	if leafPEM == "" {
		t.Fatal("returned leafPEM is empty")
	}
	block, _ := pem.Decode([]byte(leafPEM))
	if block == nil {
		t.Fatal("returned leafPEM is not a valid PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse returned cert: %v", err)
	}
	if cert.IsCA {
		t.Errorf("BUG: returned cert is a CA (CN=%q IsCA=true) : leaf selection is broken", cert.Subject.CommonName)
	}
	if cert.Subject.CommonName != "leaf.example.com" {
		t.Errorf("returned cert CN=%q, want %q", cert.Subject.CommonName, "leaf.example.com")
	}
	t.Logf("OK: returned leaf CN=%q IsCA=%v", cert.Subject.CommonName, cert.IsCA)
}

// TestLeafSelectionP7B_TwoChain verifies the P7B download path correctly returns
// the end-entity leaf from a root-first two-cert chain (root + leaf).
func TestLeafSelectionP7B_TwoChain(t *testing.T) {
	root, _, leaf, _ := buildChain(t, false)
	p7b64 := buildRootFirstP7B(t, root, leaf) // root first : bug trigger

	body, _ := json.Marshal(map[string]string{"Content": p7b64})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ctx := context.Background()
	leafPEM, _, _, diags := downloadCertificateFromKeyfactorCommand(ctx, 1, 0, newMockClient(t, srv))
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	assertLeaf(t, leafPEM)
}

// TestLeafSelectionP7B_ThreeChain verifies the P7B download path correctly returns
// the end-entity leaf from a root-first three-cert chain (root + intermediate + leaf),
// matching the DigiCert PKIaaS chain topology that triggered the customer bug.
func TestLeafSelectionP7B_ThreeChain(t *testing.T) {
	root, intermediate, leaf, _ := buildChain(t, true)
	p7b64 := buildRootFirstP7B(t, root, intermediate, leaf) // root first : bug trigger

	body, _ := json.Marshal(map[string]string{"Content": p7b64})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ctx := context.Background()
	leafPEM, _, _, diags := downloadCertificateFromKeyfactorCommand(ctx, 1, 0, newMockClient(t, srv))
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	assertLeaf(t, leafPEM)
}

// TestLeafSelectionPFX verifies the PFX recovery path (Certificates/Recover)
// correctly returns the end-entity leaf when the PFX contains a private key,
// leaf cert, and CA chain certs.
func TestLeafSelectionPFX(t *testing.T) {
	root, intermediate, leaf, leafKey := buildChain(t, true)

	// Build PFX: private key + leaf cert + CA chain (root + intermediate).
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, []*x509.Certificate{intermediate, root}, "testpassword")
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	// Mock server: POST to /Recover → PFX JSON; POST to /Download → 400 (should not be called).
	recoverBody, _ := json.Marshal(map[string]string{"PFX": pfxB64, "FileName": "cert.pfx"})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "Download") {
			t.Errorf("Download endpoint called : Recover should have succeeded")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(recoverBody)
	}))
	defer srv.Close()

	ctx := context.Background()
	// Use "PEM" format: RecoverCertificate decodes the PFX via pkcs12.DecodeChain.
	_, leafPEM, _, _, diags := recoverPrivateKeyFromKeyfactorCommand(ctx, 1, 0, "testpassword", newMockClient(t, srv), "PEM")
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
	assertLeaf(t, leafPEM)
}
