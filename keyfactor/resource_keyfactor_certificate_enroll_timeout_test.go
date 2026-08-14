package keyfactor

// Regression tests for the "duplicate certificates on enrollment timeout" bug
// (customer-reported against v2.9.1): when the client-side PFX enrollment POST
// times out but Command completes the enrollment server-side, Create returned
// an error and saved nothing to state. The next apply enrolled AGAIN, piling
// up duplicate certificates on every retry.
//
// The fix makes Create attempt recovery before failing: on a timeout-shaped
// error from EnrollPFXV2, search Command for a certificate matching the
// enrollment request (same CN, issued at/after the moment the enroll call
// started). Exactly one match is adopted into state; zero or multiple matches
// fall back to the original error with import guidance.
//
// These tests use an in-process mock HTTPS server plus an injected
// http.RoundTripper that deterministically simulates a client-side timeout on
// the Enrollment/PFX call specifically (without any real sleeping/racing),
// modeled after the mockLeafAuth/newMockClient pattern in download_leaf_test.go.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth_providers "github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	api "github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/types"
	pkcs12 "github.com/spbsoluble/go-pkcs12"
)

// syntheticTimeoutError implements net.Error to deterministically simulate a
// client-side HTTP timeout ("net/http: timeout awaiting response headers")
// without any real clock-based racing.
type syntheticTimeoutError struct{}

func (syntheticTimeoutError) Error() string   { return "net/http: timeout awaiting response headers" }
func (syntheticTimeoutError) Timeout() bool   { return true }
func (syntheticTimeoutError) Temporary() bool { return true }

// timeoutOnPathRoundTripper returns a synthetic timeout error for any request
// whose path contains timeoutPathSubstr, and passes everything else through
// to inner. callCount is incremented for every intercepted (timed-out) call,
// letting tests assert Create doesn't blindly retry the enroll call itself.
type timeoutOnPathRoundTripper struct {
	inner             http.RoundTripper
	timeoutPathSubstr string
	callCount         *int
}

func (t *timeoutOnPathRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, t.timeoutPathSubstr) {
		if t.callCount != nil {
			*t.callCount++
		}
		return nil, syntheticTimeoutError{}
	}
	return t.inner.RoundTrip(req)
}

// newTimeoutMockClient builds an api.Client wired to srv, whose requests to
// any path containing timeoutPathSubstr are intercepted and turned into a
// synthetic timeout error before ever reaching srv.
func newTimeoutMockClient(t *testing.T, srv *httptest.Server, timeoutPathSubstr string, callCount *int) *api.Client {
	t.Helper()
	tlsClient := srv.Client()
	tlsClient.Transport = &timeoutOnPathRoundTripper{
		inner: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		timeoutPathSubstr: timeoutPathSubstr,
		callCount:         callCount,
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

// buildSelfSignedLeaf creates a minimal self-signed leaf certificate and key
// for use in a test PKCS#12 blob (recovery doesn't require a full chain).
func buildSelfSignedLeaf(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

// newMinimalPFXPlan builds a CommandCertificate plan with just enough set to
// exercise enrollPFXV2 without triggering unrelated nil-list/nil-map panics
// or additional (unmocked) API calls -- modeled after the nullList/nullMap
// pattern in resource_keyfactor_certificate_unit_test.go.
func newMinimalPFXPlan(commonName, keyPassword string) *CommandCertificate {
	nullList := types.List{ElemType: types.StringType, Null: true}
	return &CommandCertificate{
		CommonName:          types.String{Value: commonName},
		CSR:                 types.String{Null: true},
		KeyPassword:         types.String{Value: keyPassword},
		CertificateTemplate: types.String{Value: "SomeTemplate"},
		EnrollmentPattern:   types.String{Null: true},
		CertificateFormat:   types.String{Null: true}, // resolves to DEFAULT_CERTIFICATE_ENROLLMENT_FORMAT ("STORE")
		DNSSANs:             nullList,
		IPSANs:              nullList,
		URISANs:             nullList,
		CollectionId:        types.Int64{Value: 0},
	}
}

// certSearchAndRecoverHandler returns an http.HandlerFunc that serves:
//   - GET  .../Certificates (search, no id/Recover suffix) -> certsToReturn as JSON
//   - POST .../Certificates/Recover                        -> {"PFX": pfxB64}
//   - anything else (e.g. EnrollmentPatterns, or a stray Enrollment/PFX call
//     that should have been intercepted by the RoundTripper) -> 404, and if
//     it's Enrollment/PFX specifically, fail the test loudly since that would
//     mean the "timeout" was never actually simulated.
func certSearchAndRecoverHandler(t *testing.T, certsToReturn []api.GetCertificateResponse, pfxB64 string) http.HandlerFunc {
	t.Helper()
	searchBody, err := json.Marshal(certsToReturn)
	if err != nil {
		t.Fatalf("marshal search response: %v", err)
	}
	recoverBody, err := json.Marshal(map[string]string{"PFX": pfxB64, "FileName": "cert.pfx"})
	if err != nil {
		t.Fatalf("marshal recover response: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "Certificates/Recover"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(recoverBody)
		case r.Method == http.MethodGet && strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "Certificates"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(searchBody)
		case strings.Contains(r.URL.Path, "Enrollment/PFX"):
			t.Errorf("Enrollment/PFX reached the mock server -- the timeout RoundTripper should have intercepted it")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_AdoptsSingleMatch is the core red->green
// regression test: EnrollPFXV2 always times out, but Command has exactly one
// certificate matching the requested CN issued after the enroll attempt
// started. Create must adopt it into state (private key recovered via the
// enrollment password) rather than returning an error that would cause the
// next apply to enroll a duplicate.
func TestUnitEnrollPFX_TimeoutRecovery_AdoptsSingleMatch(t *testing.T) {
	const (
		commonName = "tf-unit-timeout-recovery.example.com"
		password   = "TestPassword123!"
	)

	leaf, leafKey := buildSelfSignedLeaf(t, commonName)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, password)
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	orphan := api.GetCertificateResponse{
		Id:            777,
		IssuedCN:      commonName,
		Thumbprint:    "AABBCCDDEEFF00112233445566778899AABBCCDD",
		SerialNumber:  "01",
		IssuerDN:      "CN=Test Root CA",
		NotBefore:     time.Now().UTC().Format(time.RFC3339),
		CertRequestId: 999,
	}

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchAndRecoverHandler(t, []api.GetCertificateResponse{orphan}, pfxB64))
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, password)

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf("expected no error after successful orphan recovery, got: %v", diags)
	}
	if result == nil {
		t.Fatal("expected a non-nil result after orphan recovery")
	}
	if enrollAttempts != 1 {
		t.Fatalf("expected exactly 1 enrollment attempt (no blind retry), got %d", enrollAttempts)
	}
	if got := fmt.Sprintf("%v", result.ID.Value); got != "777" {
		t.Errorf("result.ID = %q, want %q (should adopt the orphaned certificate's ID)", got, "777")
	}
	if result.CertificateId.Value != 777 {
		t.Errorf("result.CertificateId = %d, want 777", result.CertificateId.Value)
	}
	if result.PrivateKey.Value == "" {
		t.Error("result.PrivateKey is empty -- private key recovery should have succeeded")
	}
	if result.PEM.Value == "" {
		t.Error("result.PEM is empty -- leaf certificate recovery should have succeeded")
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_ZeroMatches verifies that when EnrollPFXV2
// times out and NO certificate matches the requested CN in Command, Create
// returns the original timeout error (augmented with import guidance) instead
// of fabricating a result -- and, critically, does NOT loop into a second
// enrollment attempt of its own accord.
func TestUnitEnrollPFX_TimeoutRecovery_ZeroMatches(t *testing.T) {
	const commonName = "tf-unit-timeout-no-match.example.com"

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchAndRecoverHandler(t, []api.GetCertificateResponse{}, ""))
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal("expected an error when no orphaned certificate is found, got none")
	}
	if result != nil {
		t.Fatalf("expected nil result when recovery finds no match, got %+v", result)
	}
	if enrollAttempts != 1 {
		t.Fatalf("expected exactly 1 enrollment attempt, got %d", enrollAttempts)
	}

	var found bool
	for _, d := range diags.Errors() {
		if strings.Contains(d.Detail(), "terraform import") {
			found = true
		}
	}
	if !found {
		t.Error("expected the error diagnostic to mention `terraform import` guidance")
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_MultipleMatches verifies that when
// multiple certificates match the requested CN issued after the enroll
// attempt started, Create refuses to guess and returns an error rather than
// adopting an arbitrary one.
func TestUnitEnrollPFX_TimeoutRecovery_MultipleMatches(t *testing.T) {
	const commonName = "tf-unit-timeout-ambiguous.example.com"

	now := time.Now().UTC().Format(time.RFC3339)
	dupes := []api.GetCertificateResponse{
		{Id: 111, IssuedCN: commonName, NotBefore: now},
		{Id: 222, IssuedCN: commonName, NotBefore: now},
	}

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchAndRecoverHandler(t, dupes, ""))
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal("expected an error when multiple orphaned certificates match, got none")
	}
	if result != nil {
		t.Fatalf("expected nil result when recovery is ambiguous, got %+v", result)
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_IgnoresOlderCertificate verifies that a
// pre-existing certificate with the same CN but issued BEFORE the enroll
// attempt started is not mistaken for the orphaned one -- it should be
// treated as a zero-match case (fails with guidance), not adopted.
func TestUnitEnrollPFX_TimeoutRecovery_IgnoresOlderCertificate(t *testing.T) {
	const commonName = "tf-unit-timeout-stale-match.example.com"

	stale := api.GetCertificateResponse{
		Id:        333,
		IssuedCN:  commonName,
		NotBefore: time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
	}

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchAndRecoverHandler(t, []api.GetCertificateResponse{stale}, ""))
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal("expected an error -- the only matching certificate predates the enrollment attempt")
	}
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
}

// TestUnitEnrollPFX_NonTimeoutErrorNotRecovered verifies that a definitive
// rejection from Command (not a timeout) does not trigger orphan-recovery at
// all -- it should fail immediately with the original error, since nothing
// was created server-side.
func TestUnitEnrollPFX_NonTimeoutErrorNotRecovered(t *testing.T) {
	const commonName = "tf-unit-non-timeout-error.example.com"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "Enrollment/PFX") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"Message":"invalid template"}`))
			return
		}
		if strings.Contains(r.URL.Path, "Certificates") {
			t.Error("search should not be attempted for a non-timeout error")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tlsClient := srv.Client()
	tlsClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	auth := &mockLeafAuth{
		client: tlsClient,
		server: &auth_providers.Server{Host: srv.URL, APIPath: "KeyfactorAPI", SkipTLSVerify: true},
	}
	ctx := context.Background()
	client := api.NewKeyfactorClientWithAuth(auth, &ctx)

	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")

	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal("expected an error for a definitive (non-timeout) enrollment rejection")
	}
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
}
