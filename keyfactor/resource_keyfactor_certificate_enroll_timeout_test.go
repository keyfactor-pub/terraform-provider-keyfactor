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

// realisticOrphanCert builds a Command-realistic GetCertificateResponse for
// orphan-recovery tests: ImportDate reflects issuedAt (when Command recorded
// the certificate -- the correct freshness signal, see enrollmentTimeoutSkew
// in helpers.go) but NotBefore is backdated ~10 minutes from issuedAt,
// mirroring real CA behavior (EJBCA's default certificate.validityoffset is
// -10m; Microsoft ADCS's default ClockSkewMinutes is 10). A certificate
// fixture that sets NotBefore == ImportDate (as earlier tests here did)
// cannot catch a regression back to filtering on NotBefore, since real CAs
// never produce that shape.
func realisticOrphanCert(id int, commonName, templateName string, issuedAt time.Time) api.GetCertificateResponse {
	return api.GetCertificateResponse{
		Id:           id,
		IssuedCN:     commonName,
		IssuedDN:     fmt.Sprintf("CN=%s", commonName),
		TemplateName: templateName,
		ImportDate:   issuedAt.UTC().Format(time.RFC3339Nano),
		NotBefore:    issuedAt.Add(-10 * time.Minute).UTC().Format(time.RFC3339),
		NotAfter:     issuedAt.Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
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

	orphan := realisticOrphanCert(777, commonName, "SomeTemplate", time.Now().UTC())
	orphan.Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD"
	orphan.SerialNumber = "01"
	orphan.IssuerDN = "CN=Test Root CA"
	orphan.CertRequestId = 999

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

	now := time.Now().UTC()
	dupes := []api.GetCertificateResponse{
		realisticOrphanCert(111, commonName, "SomeTemplate", now),
		realisticOrphanCert(222, commonName, "SomeTemplate", now),
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

	stale := realisticOrphanCert(333, commonName, "SomeTemplate", time.Now().UTC().Add(-24*time.Hour))

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

// TestUnitEnrollPFX_TimeoutRecovery_RejectsWrongCertificateSameCN is the F2
// regression test. The original implementation identified a candidate by CN
// + freshness ONLY, so a DIFFERENT certificate sharing the requested CN --
// e.g. an unrelated concurrent enrollment for the same hostname -- could be
// silently adopted: its private key exported into Terraform state and
// revoked on destroy. Every other discriminator available from the original
// request (subject, template, CA, SANs, requester identity) must now also
// match, or Create must fall back to the original timeout error rather than
// guess.
func TestUnitEnrollPFX_TimeoutRecovery_RejectsWrongCertificateSameCN(t *testing.T) {
	const commonName = "tf-unit-wrong-cert.example.com"

	leaf, leafKey := buildSelfSignedLeaf(t, commonName)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, "TestPassword123!")
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	// wrongCert shares the requested CN and is fresh enough to pass the
	// freshness check, but was issued off a DIFFERENT template than what
	// newMinimalPFXPlan requests ("SomeTemplate") -- e.g. a concurrent,
	// unrelated enrollment for the same hostname.
	wrongCert := realisticOrphanCert(555, commonName, "UnrelatedTemplate", time.Now().UTC())
	wrongCert.IssuedDN = "CN=" + commonName + ",O=Some Unrelated Org"

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchAndRecoverHandler(t, []api.GetCertificateResponse{wrongCert}, pfxB64))
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal(
			"expected an error -- the only matching-CN certificate was issued off a different template " +
				"and must not be adopted",
		)
	}
	if result != nil {
		t.Fatalf(
			"SECURITY: adopted certificate id %d, which never matched the enrollment request's template/subject; got result %+v",
			wrongCert.Id, result,
		)
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_WarningSurfacedInDiagnostics is the F5
// regression test: the only prior record of a successful adoption was
// tflog.Warn, which `terraform apply` does not display unless TF_LOG is set.
// A successful recovery must also add an operator-visible warning
// diagnostic that names the adopted certificate.
func TestUnitEnrollPFX_TimeoutRecovery_WarningSurfacedInDiagnostics(t *testing.T) {
	const (
		commonName = "tf-unit-timeout-warning.example.com"
		password   = "TestPassword123!"
	)
	leaf, leafKey := buildSelfSignedLeaf(t, commonName)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, password)
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	orphan := realisticOrphanCert(888, commonName, "SomeTemplate", time.Now().UTC())

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchAndRecoverHandler(t, []api.GetCertificateResponse{orphan}, pfxB64))
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, password)

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf("expected a successful (warning, not error) recovery, got: %v", diags)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}

	var found bool
	for _, w := range diags.Warnings() {
		if strings.Contains(w.Detail(), "888") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning diagnostic naming the adopted certificate ID (888), got: %v", diags.Warnings())
	}
}

// certSearchAndRecoverHandlerCapturingFormat is like
// certSearchAndRecoverHandler but also records the "x-certificateformat"
// header Command received on the Recover call, exposed via gotFormat. It
// returns recoverPayloadB64 verbatim in the "PFX" JSON field regardless of
// what format was requested -- Command would return format-appropriate
// bytes in that field, but for these tests the important assertion is which
// format was actually requested (F6/F7), and that non-PKCS#12-shaped bytes
// still pass through into the right result field.
func certSearchAndRecoverHandlerCapturingFormat(
	t *testing.T,
	certsToReturn []api.GetCertificateResponse,
	recoverPayloadB64 string,
	gotFormat *string,
) http.HandlerFunc {
	t.Helper()
	searchBody, err := json.Marshal(certsToReturn)
	if err != nil {
		t.Fatalf("marshal search response: %v", err)
	}
	recoverBody, err := json.Marshal(map[string]string{"PFX": recoverPayloadB64, "FileName": "cert.bin"})
	if err != nil {
		t.Fatalf("marshal recover response: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "Certificates/Recover"):
			if gotFormat != nil {
				*gotFormat = r.Header.Get("x-certificateformat")
			}
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

// TestUnitEnrollPFX_TimeoutRecovery_JKSFormatThreaded is the F6 regression
// test: recoverOrphanedPFXEnrollment used to hardcode "PFX" when recovering
// the orphaned certificate's key material regardless of the resource's
// actual certificate_format. For certificate_format = "JKS" that meant state
// ended up holding a base64 PKCS#12 blob in the JKS field -- silently wrong
// for any downstream keytool/Java consumer. The format actually requested
// from Command must match certificate_format.
func TestUnitEnrollPFX_TimeoutRecovery_JKSFormatThreaded(t *testing.T) {
	const commonName = "tf-unit-timeout-jks.example.com"
	// Not a real JKS keystore -- just distinguishable bytes standing in for
	// "whatever Command would return for a JKS-format Recover request".
	jksPayload := base64.StdEncoding.EncodeToString([]byte("not-a-real-jks-keystore-but-distinguishable"))

	orphan := realisticOrphanCert(444, commonName, "SomeTemplate", time.Now().UTC())

	var enrollAttempts int
	var gotFormat string
	srv := httptest.NewTLSServer(
		certSearchAndRecoverHandlerCapturingFormat(t, []api.GetCertificateResponse{orphan}, jksPayload, &gotFormat),
	)
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")
	plan.CertificateFormat = types.String{Value: "JKS"}

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf("expected a successful JKS recovery (non-empty rawBytes is success for binary formats), got: %v", diags)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}
	if gotFormat != "JKS" {
		t.Errorf("Certificates/Recover was called with certificateFormat %q, want %q -- format was not threaded through", gotFormat, "JKS")
	}
	if result.JKS.Value != jksPayload {
		t.Errorf("result.JKS = %q, want the raw JKS payload %q", result.JKS.Value, jksPayload)
	}
	// PFX/Zip are not populated by the JKS branch (pre-existing, unrelated to
	// this fix) -- the important assertion is that neither field ends up
	// holding the JKS payload/wrong content.
	if result.Zip.Value == jksPayload {
		t.Errorf("result.Zip should not contain the JKS payload, got %q", result.Zip.Value)
	}
	if result.PFX.Value == jksPayload {
		t.Errorf("result.PFX should not contain the JKS payload, got %q", result.PFX.Value)
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_ZIPFormatThreadedWithDecodeTolerance is
// the F7 regression test, covering the reviewer-flagged incomplete-fix trap:
// keyfactor-go-client's RecoverCertificate has no "ZIP" case in its format
// switch, so it falls through to the default branch, which always attempts
// a PKCS#12 decode of the raw response and returns that decode error
// ALONGSIDE the (perfectly valid, just non-PKCS#12) rawBytes for a ZIP
// payload. Non-empty rawBytes must still count as success for a binary
// format here, exactly like the existing recoverOrDownloadCertificate
// tolerance -- otherwise every ZIP-format timeout recovery would fail.
func TestUnitEnrollPFX_TimeoutRecovery_ZIPFormatThreadedWithDecodeTolerance(t *testing.T) {
	const commonName = "tf-unit-timeout-zip.example.com"
	zipPayload := base64.StdEncoding.EncodeToString([]byte("PK\x03\x04-not-a-real-zip-but-distinguishable"))

	orphan := realisticOrphanCert(556, commonName, "SomeTemplate", time.Now().UTC())

	var enrollAttempts int
	var gotFormat string
	srv := httptest.NewTLSServer(
		certSearchAndRecoverHandlerCapturingFormat(t, []api.GetCertificateResponse{orphan}, zipPayload, &gotFormat),
	)
	defer srv.Close()

	client := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")
	plan.CertificateFormat = types.String{Value: "ZIP"}

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf(
			"expected the PKCS#12-decode-error-with-valid-rawBytes case to be tolerated for ZIP, got: %v", diags,
		)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}
	if gotFormat != "ZIP" {
		t.Errorf("Certificates/Recover was called with certificateFormat %q, want %q -- format was not threaded through", gotFormat, "ZIP")
	}
	if result.Zip.Value != zipPayload {
		t.Errorf("result.Zip = %q, want the raw ZIP payload %q", result.Zip.Value, zipPayload)
	}
}

// TestUnitFindOrphanedCertificateMatch_StrictDiscriminators is a focused F2
// unit test directly exercising findOrphanedCertificateMatch's discriminator
// logic: a certificate that would previously have matched on CN + freshness
// alone must now also match on subject, template, certificate authority,
// and SANs, or be rejected.
func TestUnitFindOrphanedCertificateMatch_StrictDiscriminators(t *testing.T) {
	const commonName = "tf-unit-strict-match.example.com"
	now := time.Now().UTC()

	baseSubject := &api.CertificateSubject{
		SubjectCommonName:         commonName,
		SubjectOrganization:       "Example Corp",
		SubjectOrganizationalUnit: "Engineering",
		SubjectCountry:            "US",
	}
	baseSANs := &api.SANs{DNS: []string{"alt.example.com"}}
	baseCriteria := orphanRecoveryCriteria{
		CommonName:           commonName,
		Subject:              baseSubject,
		SANs:                 baseSANs,
		Template:             "WebServer",
		CertificateAuthority: "IssuingCA1",
		EnrollStartTime:      now,
	}

	matchingCert := realisticOrphanCert(1, commonName, "WebServer", now.Add(10*time.Second))
	matchingCert.IssuedDN = "CN=" + commonName + ",OU=Engineering,O=Example Corp,C=US"
	matchingCert.CertificateAuthorityName = `ca-host.example.com\IssuingCA1`
	matchingCert.SubjectAltNameElements = []api.SubjectAltNameElements{
		{Type: sanTypeDNS, Value: "alt.example.com"},
	}

	if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{matchingCert}, baseCriteria); err != nil {
		t.Fatalf("expected matchingCert to satisfy every discriminator, got error: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(api.GetCertificateResponse) api.GetCertificateResponse
	}{
		{
			name: "different organization in subject DN",
			mutate: func(c api.GetCertificateResponse) api.GetCertificateResponse {
				c.IssuedDN = "CN=" + commonName + ",OU=Engineering,O=Some Other Org,C=US"
				return c
			},
		},
		{
			name: "different template",
			mutate: func(c api.GetCertificateResponse) api.GetCertificateResponse {
				c.TemplateName = "DifferentTemplate"
				return c
			},
		},
		{
			name: "different certificate authority",
			mutate: func(c api.GetCertificateResponse) api.GetCertificateResponse {
				c.CertificateAuthorityName = `ca-host.example.com\OtherCA`
				return c
			},
		},
		{
			name: "different SAN value",
			mutate: func(c api.GetCertificateResponse) api.GetCertificateResponse {
				c.SubjectAltNameElements = []api.SubjectAltNameElements{{Type: sanTypeDNS, Value: "different.example.com"}}
				return c
			},
		},
		{
			name: "SAN missing entirely",
			mutate: func(c api.GetCertificateResponse) api.GetCertificateResponse {
				c.SubjectAltNameElements = nil
				return c
			},
		},
		{
			name: "unparsable subject DN when subject fields must be verified",
			mutate: func(c api.GetCertificateResponse) api.GetCertificateResponse {
				c.IssuedDN = "not a valid dn at all"
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrong := tt.mutate(matchingCert)
			if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{wrong}, baseCriteria); err == nil {
				t.Fatalf("expected %q to be rejected (fail closed), but it was accepted as a match", tt.name)
			}
		})
	}
}

// TestUnitFindOrphanedCertificateMatch_RequesterIdentityMismatch is a
// focused F2 unit test covering the requester-identity discriminator: a
// candidate whose RequesterName doesn't match the identity this provider is
// authenticated as must be rejected, even though Command did return
// requester information.
func TestUnitFindOrphanedCertificateMatch_RequesterIdentityMismatch(t *testing.T) {
	const commonName = "tf-unit-requester-mismatch.example.com"
	now := time.Now().UTC()
	cert := realisticOrphanCert(1, commonName, "", now)
	cert.RequesterName = "someone-else@example.com"

	criteria := orphanRecoveryCriteria{
		CommonName:      commonName,
		EnrollStartTime: now,
		Identity:        orphanRecoveryIdentity{candidates: []string{"expected-service-account"}},
	}
	if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{cert}, criteria); err == nil {
		t.Fatal("expected a requester-identity mismatch to be rejected")
	}

	// Sanity: a matching identity (case-insensitively) succeeds.
	cert.RequesterName = "Expected-Service-Account"
	if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{cert}, criteria); err != nil {
		t.Fatalf("expected a matching requester identity to succeed, got: %v", err)
	}
}

// TestUnitFindOrphanedCertificateMatch_TruncatedResultSet is the F3
// regression test: ListCertificates has no page-size/ReturnLimit control in
// this SDK version, and Command's documented default ReturnLimit for
// GET /Certificates is 50. A result set at or above that size must never be
// treated as "the whole story" -- even when every discriminator happens to
// narrow it down to exactly one candidate, additional matches beyond the
// (possibly) truncated page cannot be ruled out.
func TestUnitFindOrphanedCertificateMatch_TruncatedResultSet(t *testing.T) {
	const commonName = "tf-unit-truncated.example.com"
	now := time.Now().UTC()

	// Build exactly certificatesListReturnLimitDefault (50) results. Only
	// ONE of them (the last) actually satisfies the template discriminator --
	// if truncation weren't accounted for, this would otherwise look like a
	// safe, unique match.
	var certs []api.GetCertificateResponse
	for i := 0; i < certificatesListReturnLimitDefault; i++ {
		certs = append(certs, realisticOrphanCert(i+1, commonName, "WrongTemplate", now))
	}
	certs[len(certs)-1].TemplateName = "RightTemplate"

	criteria := orphanRecoveryCriteria{
		CommonName:      commonName,
		Template:        "RightTemplate",
		EnrollStartTime: now,
	}

	if _, err := findOrphanedCertificateMatch(certs, criteria); err == nil {
		t.Fatal("expected a truncation-shaped ambiguity error for a full page of results, got a confident match")
	} else if !strings.Contains(err.Error(), "page") {
		t.Errorf("expected the error to explain the truncation risk, got: %v", err)
	}

	// Sanity: one fewer result (below the page-size threshold) is NOT
	// treated as possibly truncated, and the single genuine match succeeds.
	certsBelowLimit := certs[1:] // 49 results, still contains the one RightTemplate match
	match, err := findOrphanedCertificateMatch(certsBelowLimit, criteria)
	if err != nil {
		t.Fatalf("expected a confident match below the page-size threshold, got error: %v", err)
	}
	if match.Id != certs[len(certs)-1].Id {
		t.Errorf("matched wrong certificate: got id %d, want %d", match.Id, certs[len(certs)-1].Id)
	}
}
