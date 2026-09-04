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
	"strconv"
	"strings"
	"testing"
	"time"

	auth_providers "github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	api "github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
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

// newTimeoutMockClient builds an api.Client (legacy) and a *keyfactor.APIClient
// (v24 SDK, used by the F4 paginated orphan search) both wired to srv, whose
// requests to any path containing timeoutPathSubstr are intercepted and
// turned into a synthetic timeout error before ever reaching srv.
func newTimeoutMockClient(
	t *testing.T, srv *httptest.Server, timeoutPathSubstr string, callCount *int,
) (*api.Client, *keyfactor.APIClient) {
	t.Helper()
	tlsClient := srv.Client()
	tlsClient.Transport = &timeoutOnPathRoundTripper{
		inner: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		timeoutPathSubstr: timeoutPathSubstr,
		callCount:         callCount,
	}
	// The legacy api.Client and the v24 SDK client disagree on the shape of
	// auth_providers.Server.Host: api.Client wants a scheme-prefixed URL plus
	// a separate APIPath (mirrors newCertAPIMockAuthConfig in
	// test_helpers_test.go), while the SDK client wants a bare "host:port"
	// with no scheme and folds APIPath into its own default (mirrors
	// newSDKMockAuthConfig). Both share the same tlsClient/RoundTripper so
	// the timeout injection applies to either client's requests.
	legacyAuth := &mockLeafAuth{
		client: tlsClient,
		server: &auth_providers.Server{
			Host:          srv.URL,
			APIPath:       "KeyfactorAPI",
			SkipTLSVerify: true,
		},
	}
	sdkAuth := &mockLeafAuth{
		client: tlsClient,
		server: &auth_providers.Server{
			Host:          strings.TrimPrefix(srv.URL, "https://"),
			SkipTLSVerify: true,
		},
	}
	ctx := context.Background()
	return api.NewKeyfactorClientWithAuth(legacyAuth, &ctx), keyfactor.NewAPIClientWithAuth(sdkAuth)
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

// certsToSDKSearchJSON marshals certs the way these mock handlers need to for
// the GET .../Certificates search response, EXCEPT it drops two legacy
// api.GetCertificateResponse fields whose JSON shape doesn't line up with the
// v24 SDK's CertificatesCertificateRetrievalResponse (what
// searchCertificatesForOrphanRecovery -- the F4 fix -- now actually decodes
// the search response into): PrincipalId (string on the legacy struct,
// NullableInt32 on the SDK struct) and RevocationEffDate (empty string when
// unset on the legacy struct, but NullableTime -- via time.Time's stock
// UnmarshalJSON -- on the SDK struct, which rejects ""). Neither field is
// read by any orphan-recovery discriminator, so dropping them from these
// test fixtures' wire representation doesn't weaken any assertion; without
// this, every one of these mock responses would fail to decode on the
// client side now that the search goes through the SDK client instead of
// the legacy client's ListCertificates.
func certsToSDKSearchJSON(t *testing.T, certs []api.GetCertificateResponse) []byte {
	t.Helper()
	raw, err := json.Marshal(certs)
	if err != nil {
		t.Fatalf("marshal certs: %v", err)
	}
	var generic []map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("re-decode certs as generic JSON: %v", err)
	}
	for _, m := range generic {
		delete(m, "PrincipalId")
		delete(m, "RevocationEffDate")
	}
	body, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal sanitized certs: %v", err)
	}
	return body
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
	searchBody := certsToSDKSearchJSON(t, certsToReturn)
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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

// TestUnitFindOrphanedCertificateMatch_DeduplicatesSameIdAcrossPages is the
// regression test for the dedup half of the fix:
// searchCertificatesForOrphanRecovery's pagination can -- despite the
// companion Id-ascending sort fix -- still surface the SAME certificate row
// twice in the concatenated result set if a certificate for this exact CN is
// inserted while a multi-page search is in flight (e.g. the last row of page
// N reappears, shifted, as the first row of page N+1). Before the fix,
// findOrphanedCertificateMatch had no dedup: two structurally-identical
// entries for the same certificate trivially satisfy every discriminator and
// trip the len(candidates) > 1 "ambiguous" refusal, spuriously refusing an
// otherwise-uniquely-recoverable orphan. The fix dedups by certificate Id.
func TestUnitFindOrphanedCertificateMatch_DeduplicatesSameIdAcrossPages(t *testing.T) {
	const commonName = "tf-unit-dedup-across-pages.example.com"
	now := time.Now().UTC()

	genuine := realisticOrphanCert(999, commonName, "SomeTemplate", now)
	// Simulate the exact symptom unsorted/racing offset-based pagination can
	// produce under concurrent writes: the SAME certificate row appears
	// twice in the fully-paginated, concatenated result set.
	certsWithDuplicate := []api.GetCertificateResponse{genuine, genuine}

	criteria := orphanRecoveryCriteria{
		CommonName:      commonName,
		Template:        "SomeTemplate",
		EnrollStartTime: now,
	}

	match, err := findOrphanedCertificateMatch(certsWithDuplicate, criteria)
	if err != nil {
		t.Fatalf(
			"expected a certificate Id appearing twice in the paginated result set to collapse to a single "+
				"candidate, not trigger a spurious ambiguous-match refusal, got: %v", err,
		)
	}
	if match.Id != genuine.Id {
		t.Errorf("matched wrong certificate: got id %d, want %d", match.Id, genuine.Id)
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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
	sdkClient := keyfactor.NewAPIClientWithAuth(auth)

	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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
// format was actually requested, and that non-PKCS#12-shaped bytes
// still pass through into the right result field.
func certSearchAndRecoverHandlerCapturingFormat(
	t *testing.T,
	certsToReturn []api.GetCertificateResponse,
	recoverPayloadB64 string,
	gotFormat *string,
) http.HandlerFunc {
	t.Helper()
	searchBody := certsToSDKSearchJSON(t, certsToReturn)
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
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
	// Template/TemplateId intentionally use a SHORT name + resolved ID, while
	// matchingCert below carries the corresponding DISPLAY name (as Command's
	// certificate record always does) plus the SAME ID -- an identical-string
	// fixture on both sides (as this test previously used) can't catch a
	// regression back to comparing TemplateName strings directly (see F1:
	// orphanRecoveryTemplateMatches now compares TemplateId when available,
	// exactly because the request's short name almost never equals Command's
	// TemplateName display value).
	baseCriteria := orphanRecoveryCriteria{
		CommonName:           commonName,
		Subject:              baseSubject,
		SANs:                 baseSANs,
		Template:             "WebServer_shortname",
		TemplateId:           42,
		CertificateAuthority: "IssuingCA1",
		EnrollStartTime:      now,
	}

	matchingCert := realisticOrphanCert(1, commonName, "Web Server (Enhanced)", now.Add(10*time.Second))
	matchingCert.TemplateId = 42
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
			name: "different template (by ID -- name comparison alone would miss this)",
			mutate: func(c api.GetCertificateResponse) api.GetCertificateResponse {
				c.TemplateId = 99
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

// TestUnitFindOrphanedCertificateMatch_ShortNameVsDisplayNameTemplate is the
// F1 regression test, using the EXACT real string pair recorded in
// testdata/cassettes/certificate_resource_pfx_template_only.yaml: an
// enrollment request configured with certificate_template =
// "Server_tlsServerAuth-1y" (the schema's documented, common short-name
// form, and what PFXArgs.Template actually carries) produces a certificate
// whose TemplateName comes back from Command as "Server (tlsServerAuth-1y)"
// (the display name). Before the fix, orphanRecoveryTemplateMatches compared
// those two strings directly and NEVER matched for this -- the mainstream,
// cassette-covered, template-only-no-pattern -- case, so recovery silently
// never fired and every timeout on this path degraded straight back to the
// duplicate-certificate bug. Resolving the short name to Command's numeric
// TemplateId (4 in the cassette) and comparing IDs fixes it regardless of
// which name form either side is expressed in.
func TestUnitFindOrphanedCertificateMatch_ShortNameVsDisplayNameTemplate(t *testing.T) {
	const (
		commonName          = "tf-unit-pfx-tplonly-456775000.example.com"
		shortTemplateName   = "Server_tlsServerAuth-1y" // PFXArgs.Template / certificate_template, per the cassette
		displayTemplateName = "Server (tlsServerAuth-1y)"
		templateId          = 4 // cassette's Templates[].Id / GetCertificateResponse.TemplateId
	)
	now := time.Now().UTC()

	cert := realisticOrphanCert(3806, commonName, displayTemplateName, now)
	cert.TemplateId = templateId

	// Without a resolved TemplateId (old behavior, or a failed lookup),
	// comparing the request's short name directly against Command's display
	// name never matches -- reproducing the original bug.
	criteriaNameOnly := orphanRecoveryCriteria{
		CommonName:      commonName,
		Template:        shortTemplateName,
		EnrollStartTime: now,
	}
	if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{cert}, criteriaNameOnly); err == nil {
		t.Fatal(
			"expected a name-only comparison between the short enrollment-request name and Command's display " +
				"name to fail to match (this is the bug F1 fixes by preferring ID-based comparison) -- if this " +
				"now succeeds, orphanRecoveryTemplateMatches's fallback path silently changed",
		)
	}

	// With the resolved TemplateId (what enrollPFXV2 now does via
	// resolveTemplateIDByName before building orphanRecoveryCriteria), the
	// same short-name request correctly matches the display-named candidate.
	criteriaWithId := criteriaNameOnly
	criteriaWithId.TemplateId = templateId
	match, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{cert}, criteriaWithId)
	if err != nil {
		t.Fatalf(
			"expected ID-based template matching to succeed for the short-name-vs-display-name case, got: %v", err,
		)
	}
	if match.Id != cert.Id {
		t.Errorf("matched wrong certificate: got id %d, want %d", match.Id, cert.Id)
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

// TestUnitOrphanRecoveryIdentityForClient_KerberosCCacheWithoutUsername_MarkedPermanentlyUnavailable
// is the regression test for the auth-config-detection half of
// the fix: keyfactor-auth-client-go's CommandAuthConfigKerberos never
// requires or populates Username when authenticating via kerberos_ccache
// without an explicit kerberos_username, so GetServerConfig().Username is
// ALWAYS empty for that auth mode -- a permanent, structural gap, not the
// ordinary "nothing relevant happened to be configured" case every other
// auth mode can also hit incidentally. orphanRecoveryIdentityForClient must
// distinguish the two so callers can treat this case as reduced confidence
// rather than silently treating "not populated" as "nothing to verify".
func TestUnitOrphanRecoveryIdentityForClient_KerberosCCacheWithoutUsername_MarkedPermanentlyUnavailable(t *testing.T) {
	ctx := context.Background()

	kerberosCCacheAuth := &mockLeafAuth{
		client: &http.Client{},
		server: &auth_providers.Server{
			AuthType:       "kerberos",
			KerberosCCache: "/tmp/krb5cc_1000",
			// Username intentionally left blank -- the kerberos_ccache-
			// without-kerberos_username case this fix covers.
		},
	}
	kerberosClient := api.NewKeyfactorClientWithAuth(kerberosCCacheAuth, &ctx)

	identity := orphanRecoveryIdentityForClient(kerberosClient)
	if len(identity.candidates) != 0 {
		t.Fatalf("expected no identity candidates for Kerberos-ccache auth without a username, got %v", identity.candidates)
	}
	if !identity.permanentlyUnavailable {
		t.Fatal(
			"expected the identity discriminator to be marked permanentlyUnavailable for Kerberos-ccache auth " +
				"without an explicit username -- this is a KNOWN structural gap, not an incidental " +
				"'nothing configured' case, and must be handled as reduced confidence rather than a silent no-op",
		)
	}

	// Sanity: a DIFFERENT auth mode with no username configured is NOT this
	// known-structural case and must not be flagged permanentlyUnavailable.
	basicAuth := &mockLeafAuth{
		client: &http.Client{},
		server: &auth_providers.Server{AuthType: "basic"},
	}
	basicClient := api.NewKeyfactorClientWithAuth(basicAuth, &ctx)
	basicIdentity := orphanRecoveryIdentityForClient(basicClient)
	if basicIdentity.permanentlyUnavailable {
		t.Error("expected non-Kerberos-ccache auth with no username configured to NOT be flagged permanentlyUnavailable")
	}

	// Sanity: Kerberos WITH an explicit username populates candidates
	// normally and is not flagged permanentlyUnavailable.
	kerberosWithUsernameAuth := &mockLeafAuth{
		client: &http.Client{},
		server: &auth_providers.Server{
			AuthType:       "kerberos",
			KerberosCCache: "/tmp/krb5cc_1000",
			Username:       "svc-terraform",
		},
	}
	kerberosWithUsernameClient := api.NewKeyfactorClientWithAuth(kerberosWithUsernameAuth, &ctx)
	kerberosWithUsernameIdentity := orphanRecoveryIdentityForClient(kerberosWithUsernameClient)
	if kerberosWithUsernameIdentity.permanentlyUnavailable {
		t.Error("expected Kerberos-ccache auth WITH an explicit username to NOT be flagged permanentlyUnavailable")
	}
	if len(kerberosWithUsernameIdentity.candidates) == 0 {
		t.Error("expected Kerberos-ccache auth WITH an explicit username to populate identity candidates normally")
	}
}

// TestUnitFindOrphanedCertificateMatch_KerberosCCacheIdentityUnavailable_TightensFreshnessEvenWithTemplateAndCA
// is the regression test proving the mitigation is a real,
// active behavior change and not a documentation-only no-op: when the
// requester-identity discriminator is known permanently unavailable
// (Kerberos-ccache without a username), findOrphanedCertificateMatch must
// tighten the freshness window to enrollmentTimeoutSkewTightened even when
// Template and CertificateAuthority are BOTH populated -- i.e. even OUTSIDE
// weakSignalPath, since this request is independently missing a
// discriminator other configurations would have.
func TestUnitFindOrphanedCertificateMatch_KerberosCCacheIdentityUnavailable_TightensFreshnessEvenWithTemplateAndCA(t *testing.T) {
	const commonName = "tf-unit-kerberos-ccache-identity.example.com"
	now := time.Now().UTC()

	// 90s stale: inside enrollmentTimeoutSkew (2m) but outside
	// enrollmentTimeoutSkewTightened (30s).
	borderline := realisticOrphanCert(1, commonName, "SomeTemplate", now.Add(-90*time.Second))
	borderline.CertificateAuthorityName = `ca-host.example.com\IssuingCA1`

	richDiscriminatorCriteria := orphanRecoveryCriteria{
		CommonName:           commonName,
		EnrollStartTime:      now,
		Template:             "SomeTemplate",
		CertificateAuthority: "IssuingCA1",
	}

	// Baseline: Template and CertificateAuthority are BOTH populated (not
	// weakSignalPath) and the identity discriminator is simply not in play
	// (zero value, not the Kerberos-ccache case) -- the untightened
	// (2-minute) window applies and the 90s-stale candidate is accepted.
	if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{borderline}, richDiscriminatorCriteria); err != nil {
		t.Fatalf("expected the discriminator-rich path to accept a 90s-stale candidate, got: %v", err)
	}

	// Same request, same staleness, but the requester-identity discriminator
	// is now known permanently unavailable (Kerberos-ccache without a
	// username) -- this must tighten the freshness window even though
	// Template/CertificateAuthority are populated.
	kerberosCriteria := richDiscriminatorCriteria
	kerberosCriteria.Identity = orphanRecoveryIdentity{permanentlyUnavailable: true}
	if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{borderline}, kerberosCriteria); err == nil {
		t.Fatal(
			"expected the tightened freshness window to reject a 90s-stale candidate once the requester-identity " +
				"discriminator is known permanently unavailable (Kerberos-ccache without username), even with " +
				"Template/CertificateAuthority both populated -- if this now succeeds, the F3 mitigation silently " +
				"stopped applying",
		)
	}
}

// TestUnitFindOrphanedCertificateMatch_PatternBasedPath_TightenedFreshnessWindow
// is an F2 regression test: when Template and CertificateAuthority are both
// unavailable as discriminators (weakSignalPath -- the mainstream v25+
// enrollment-pattern path, where Template is deliberately blanked and CA is
// commonly left unset), CommonName + freshness + requester identity are
// carrying more of the narrowing burden than in the template/CA-populated
// path, so the freshness window is tightened from enrollmentTimeoutSkew (2m)
// to enrollmentTimeoutSkewTightened (30s). A candidate 90 seconds stale sits
// inside the old (2-minute) window but outside the tightened one: it must be
// REJECTED when Template/CA are both empty, but still ACCEPTED when either
// one is populated (the discriminator-rich path keeps the wider margin).
func TestUnitFindOrphanedCertificateMatch_PatternBasedPath_TightenedFreshnessWindow(t *testing.T) {
	const commonName = "tf-unit-pattern-based-freshness.example.com"
	now := time.Now().UTC()

	// 90s stale: inside enrollmentTimeoutSkew (2m) but outside
	// enrollmentTimeoutSkewTightened (30s).
	borderline := realisticOrphanCert(1, commonName, "", now.Add(-90*time.Second))

	patternBasedCriteria := orphanRecoveryCriteria{
		CommonName:      commonName,
		EnrollStartTime: now,
		// Template and CertificateAuthority intentionally left blank -- this
		// is the enrollment-pattern path (see orphanRecoveryCriteria).
	}
	if _, err := findOrphanedCertificateMatch([]api.GetCertificateResponse{borderline}, patternBasedCriteria); err == nil {
		t.Fatal(
			"expected the tightened freshness window to reject a 90s-stale candidate in the pattern-based path " +
				"(Template and CertificateAuthority both empty), but it was accepted",
		)
	}

	// Sanity: the SAME candidate, at the SAME staleness, is accepted once
	// Template is populated -- proving the tightening is scoped to the
	// weak-signal path and doesn't regress the discriminator-rich path.
	templatePopulatedCriteria := patternBasedCriteria
	templatePopulatedCriteria.Template = "SomeTemplate"
	borderlineWithTemplate := borderline
	borderlineWithTemplate.TemplateName = "SomeTemplate"
	if _, err := findOrphanedCertificateMatch(
		[]api.GetCertificateResponse{borderlineWithTemplate}, templatePopulatedCriteria,
	); err != nil {
		t.Fatalf(
			"expected the untightened (2-minute) window to still accept the same 90s-stale candidate once "+
				"Template is populated, got: %v", err,
		)
	}
}

// certSearchRecoverAndContextHandler is like certSearchAndRecoverHandler, but
// also serves GET .../Certificates/{id} (no query string -- matching what
// GetCertificateContext sends when called with only Id set) from
// contextResponses, keyed by certificate ID. Used by the F2
// EnrollmentPatternId-confirmation tests: that lookup goes through the
// LEGACY api.Client (GetCertificateContext), which decodes directly into
// api.GetCertificateResponse, so -- unlike the SDK-client search responses
// elsewhere in this file -- these bodies do NOT need certsToSDKSearchJSON's
// field sanitization.
func certSearchRecoverAndContextHandler(
	t *testing.T,
	searchCerts []api.GetCertificateResponse,
	contextResponses map[int]api.GetCertificateResponse,
	pfxB64 string,
) http.HandlerFunc {
	t.Helper()
	searchBody := certsToSDKSearchJSON(t, searchCerts)
	recoverBody, err := json.Marshal(map[string]string{"PFX": pfxB64, "FileName": "cert.pfx"})
	if err != nil {
		t.Fatalf("marshal recover response: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		trimmed := strings.TrimRight(r.URL.Path, "/")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "Certificates/Recover"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(recoverBody)
		case r.Method == http.MethodGet && strings.HasSuffix(trimmed, "Certificates"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(searchBody)
		case r.Method == http.MethodGet && strings.Contains(trimmed, "Certificates/"):
			idStr := trimmed[strings.LastIndex(trimmed, "/")+1:]
			id, convErr := strconv.Atoi(idStr)
			if convErr != nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			certCtx, ok := contextResponses[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"Message":"not found"}`))
				return
			}
			body, marshalErr := json.Marshal(certCtx)
			if marshalErr != nil {
				t.Fatalf("marshal context response: %v", marshalErr)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		case strings.Contains(r.URL.Path, "Enrollment/PFX"):
			t.Errorf("Enrollment/PFX reached the mock server -- the timeout RoundTripper should have intercepted it")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_EnrollmentPatternIdMismatchRejected
// is an F2 regression test: in the pattern-based path (weakSignalPath), the
// sole surviving candidate is cross-checked against the enrollment pattern
// this request actually resolved, via a follow-up GetCertificateContext call
// (25.1.0+ Command exposes EnrollmentPatternId there). An explicit
// disagreement must be rejected outright, even though CN/freshness/requester
// all matched.
func TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_EnrollmentPatternIdMismatchRejected(t *testing.T) {
	const (
		commonName = "tf-unit-pattern-mismatch.example.com"
		password   = "TestPassword123!"
	)
	now := time.Now().UTC()
	orphan := realisticOrphanCert(4242, commonName, "", now)

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchRecoverAndContextHandler(
		t,
		[]api.GetCertificateResponse{orphan},
		map[int]api.GetCertificateResponse{4242: {Id: 4242, EnrollmentPatternId: 2}}, // request resolved pattern 1
		"", // Recover must never be reached -- rejected before that point
	))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, password)
	plan.EnrollmentPattern = types.String{Value: "1"} // numeric ID -> no pattern-lookup network call needed

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal(
			"expected an error: the candidate's EnrollmentPatternId (2) disagrees with the request's resolved " +
				"enrollment pattern (1)",
		)
	}
	if result != nil {
		t.Fatalf("expected nil result for an enrollment-pattern disagreement, got %+v", result)
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_EnrollmentPatternIdAgreementSucceeds
// is the F2 sanity counterpart: when the candidate's EnrollmentPatternId
// agrees with the request's resolved pattern, recovery succeeds.
func TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_EnrollmentPatternIdAgreementSucceeds(t *testing.T) {
	const (
		commonName = "tf-unit-pattern-agreement.example.com"
		password   = "TestPassword123!"
	)
	leaf, leafKey := buildSelfSignedLeaf(t, commonName)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, password)
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	now := time.Now().UTC()
	orphan := realisticOrphanCert(5252, commonName, "", now)

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchRecoverAndContextHandler(
		t,
		[]api.GetCertificateResponse{orphan},
		map[int]api.GetCertificateResponse{5252: {Id: 5252, EnrollmentPatternId: 1}}, // agrees
		pfxB64,
	))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, password)
	plan.EnrollmentPattern = types.String{Value: "1"}

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf("expected recovery to succeed when EnrollmentPatternId agrees, got: %v", diags)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_UnknownEnrollmentPatternIdNotRejected
// is the F2 "cannot verify" case: a pre-25.1 Command server (or any response
// that simply omits EnrollmentPatternId) means the confirmation signal isn't
// available -- that must NOT be treated as a mismatch. Recovery proceeds on
// the already-tightened freshness window alone, per the documented residual
// risk.
func TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_UnknownEnrollmentPatternIdNotRejected(t *testing.T) {
	const (
		commonName = "tf-unit-pattern-unknown.example.com"
		password   = "TestPassword123!"
	)
	leaf, leafKey := buildSelfSignedLeaf(t, commonName)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, password)
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	now := time.Now().UTC()
	orphan := realisticOrphanCert(6363, commonName, "", now)

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchRecoverAndContextHandler(
		t,
		[]api.GetCertificateResponse{orphan},
		map[int]api.GetCertificateResponse{6363: {Id: 6363}}, // EnrollmentPatternId omitted (pre-25.1 server)
		pfxB64,
	))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, password)
	plan.EnrollmentPattern = types.String{Value: "1"}

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf("expected recovery to succeed when EnrollmentPatternId cannot be verified, got: %v", diags)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_EnrollmentPatternIdCrossCheckErrorRefusesAdoption
// is the regression test: a FAILED GetCertificateContext
// cross-check call (as opposed to a successful call whose response simply
// omits EnrollmentPatternId -- the "cannot verify" case covered by
// TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_UnknownEnrollmentPatternIdNotRejected
// above) must NOT be silently treated the same way. Before the fix, an
// errored confirmation call only logged a tflog.Warn (invisible without
// TF_LOG) and proceeded to adopt on the freshness-only signal alone --
// silently degrading to a weaker safety level than the earlier fix established for
// exactly this weak-signal path, with no operator-visible record
// distinguishing "the check ran and passed" from "the check errored and was
// skipped". The fix fails closed: refuse the adoption with a diagnostic that
// explicitly names the failed compensating control, distinct from both the
// generic "adopted" success warning and the "disagreement" rejection.
func TestUnitEnrollPFX_TimeoutRecovery_PatternBasedPath_EnrollmentPatternIdCrossCheckErrorRefusesAdoption(t *testing.T) {
	const (
		commonName = "tf-unit-pattern-crosscheck-error.example.com"
		password   = "TestPassword123!"
	)
	now := time.Now().UTC()
	orphan := realisticOrphanCert(7070, commonName, "", now)

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchRecoverAndContextHandler(
		t,
		[]api.GetCertificateResponse{orphan},
		// contextResponses intentionally omits 7070 entirely -- simulating a
		// FAILED GetCertificateContext call (404/error), not a successful
		// call whose response simply lacks EnrollmentPatternId.
		map[int]api.GetCertificateResponse{},
		"", // Recover must never be reached -- refused before that point
	))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, password)
	plan.EnrollmentPattern = types.String{Value: "1"}

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal("expected an error: the EnrollmentPatternId cross-check call itself failed and must not fail open")
	}
	if result != nil {
		t.Fatalf("expected nil result when the compensating cross-check errors, got %+v", result)
	}

	var found bool
	for _, d := range diags.Errors() {
		if strings.Contains(d.Detail(), "could NOT be performed") {
			found = true
		}
		// This must be a DISTINCT diagnostic from both the generic
		// "adopted" success warning text and the "issued under enrollment
		// pattern ... not the requested pattern" disagreement-rejection
		// text -- an operator must be able to tell this apart from either.
		if strings.Contains(d.Detail(), "adopting it into state instead of retrying") {
			t.Error("cross-check-error diagnostic must not reuse the success/adoption warning text")
		}
		if strings.Contains(d.Detail(), "not the requested pattern") {
			t.Error("cross-check-error diagnostic must not reuse the explicit-disagreement rejection text")
		}
	}
	if !found {
		t.Errorf(
			"expected the error diagnostic to explicitly name the failed compensating control, got: %v",
			diags.Errors(),
		)
	}
}

// certPaginatedSearchAndRecoverHandler is like certSearchAndRecoverHandler,
// but the GET .../Certificates search response is genuinely paginated
// according to the PageReturned/ReturnLimit query parameters the v24 SDK
// client sends (see searchCertificatesForOrphanRecovery in helpers.go),
// slicing allCerts into pages of certificatesOrphanSearchPageSize. Used by
// the F4 regression tests below to prove the fix: a CN-scoped result set
// larger than a single page is now followed to completion via real
// pagination, instead of the old guard that refused outright the moment a
// single page came back full.
func certPaginatedSearchAndRecoverHandler(t *testing.T, allCerts []api.GetCertificateResponse, pfxB64 string) http.HandlerFunc {
	t.Helper()
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
			page, convErr := strconv.Atoi(r.URL.Query().Get("PageReturned"))
			if convErr != nil || page < 1 {
				page = 1
			}
			start := (page - 1) * certificatesOrphanSearchPageSize
			end := start + certificatesOrphanSearchPageSize
			var pageCerts []api.GetCertificateResponse
			if start < len(allCerts) {
				if end > len(allCerts) {
					end = len(allCerts)
				}
				pageCerts = allCerts[start:end]
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certsToSDKSearchJSON(t, pageCerts))
		case strings.Contains(r.URL.Path, "Enrollment/PFX"):
			t.Errorf("Enrollment/PFX reached the mock server -- the timeout RoundTripper should have intercepted it")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_PaginatesPastOldTruncationGuard_AdoptsSingleMatch
// is the F4 regression test for scenario (a): the OLD guard refused
// PERMANENTLY and UNCONDITIONALLY the instant a single, un-paginated page of
// CN-scoped search results came back at Command's default page size (50) --
// true even when a documented, supported setting (revoke_on_destroy = false,
// or renewal_config.revoke_on_renew = false) leaves many past certificates
// for a repeatedly-cycled CN active and unexpired. This reproduces exactly
// that shape (59 stale, wrong-template "noise" certificates plus one fresh,
// correctly-templated genuine orphan -- 60 total, past the old 50-result
// guard) and asserts recovery now succeeds by paginating to completion
// instead of refusing outright.
func TestUnitEnrollPFX_TimeoutRecovery_PaginatesPastOldTruncationGuard_AdoptsSingleMatch(t *testing.T) {
	const (
		commonName = "tf-unit-many-prior-certs.example.com"
		password   = "TestPassword123!"
	)

	leaf, leafKey := buildSelfSignedLeaf(t, commonName)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, password)
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	now := time.Now().UTC()
	var certs []api.GetCertificateResponse
	for i := 0; i < 59; i++ {
		// Stale (48h old) and off-template -- filtered out by the existing
		// discriminators regardless, but their SHEER COUNT is what the old
		// guard choked on before ever reaching that discriminator logic.
		certs = append(certs, realisticOrphanCert(i+1, commonName, "WrongTemplate", now.Add(-48*time.Hour)))
	}
	genuine := realisticOrphanCert(999, commonName, "SomeTemplate", now)
	certs = append(certs, genuine) // 60 total, spanning 2 pages of 50

	var enrollAttempts int
	srv := httptest.NewTLSServer(certPaginatedSearchAndRecoverHandler(t, certs, pfxB64))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, password)

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf(
			"expected the >50-total-but-one-real-match case to succeed via full pagination -- this is exactly "+
				"the revoke_on_destroy=false CI-cycling scenario the old single-page guard permanently broke -- "+
				"got: %v", diags,
		)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}
	if result.CertificateId.Value != 999 {
		t.Errorf(
			"result.CertificateId = %d, want 999 (the sole genuine match, only findable via full pagination)",
			result.CertificateId.Value,
		)
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_PaginatesFully_StillRejectsAmbiguousMatch
// is the F4 regression test for scenario (b): even after paginating a
// CN-scoped result set to completion, a genuine ambiguity (two candidates
// that both satisfy every discriminator) must still be refused -- pagination
// fixes truncation-shaped false refusals, it must not weaken the existing
// "more than one candidate means refuse" safety property.
func TestUnitEnrollPFX_TimeoutRecovery_PaginatesFully_StillRejectsAmbiguousMatch(t *testing.T) {
	const commonName = "tf-unit-paginated-ambiguous.example.com"
	now := time.Now().UTC()

	var certs []api.GetCertificateResponse
	for i := 0; i < 55; i++ {
		certs = append(certs, realisticOrphanCert(i+1, commonName, "WrongTemplate", now.Add(-48*time.Hour)))
	}
	// Two fresh, correctly-templated candidates spread across the tail of the
	// paginated result set -- genuinely ambiguous even once the complete set
	// is considered.
	certs = append(
		certs,
		realisticOrphanCert(9001, commonName, "SomeTemplate", now),
		realisticOrphanCert(9002, commonName, "SomeTemplate", now),
	)

	var enrollAttempts int
	srv := httptest.NewTLSServer(certPaginatedSearchAndRecoverHandler(t, certs, ""))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal("expected an error: two candidates remain ambiguous even after full pagination")
	}
	if result != nil {
		t.Fatalf("expected nil result for an ambiguous multi-match, got %+v", result)
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_HardCapStillRefusesPathologicalResultSet
// proves certificatesOrphanSearchHardCap still bounds the pagination loop:
// a CN-scoped search that never terminates naturally (every page comes back
// completely full) must eventually refuse rather than paginate forever.
func TestUnitEnrollPFX_TimeoutRecovery_HardCapStillRefusesPathologicalResultSet(t *testing.T) {
	const commonName = "tf-unit-hardcap.example.com"
	now := time.Now().UTC()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "Certificates"):
			var page []api.GetCertificateResponse
			for i := 0; i < certificatesOrphanSearchPageSize; i++ {
				page = append(page, realisticOrphanCert(i+1, commonName, "SomeTemplate", now))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certsToSDKSearchJSON(t, page))
		case strings.Contains(r.URL.Path, "Enrollment/PFX"):
			t.Errorf("Enrollment/PFX reached the mock server -- the timeout RoundTripper should have intercepted it")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}

	var enrollAttempts int
	srv := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, "TestPassword123!")

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if !diags.HasError() {
		t.Fatal("expected the hard cap to refuse a pathologically large, never-terminating result set")
	}
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
}

// certPaginatedSearchOverlapHandler is like certPaginatedSearchAndRecoverHandler,
// but simulates the exact under-concurrent-writes hazard the dedup fix above addresses:
// unsorted, offset-based pagination can return the SAME row shifted across a
// page boundary when a new row is inserted for the same CN while a
// multi-page search is in flight. Page 1 returns allCerts[:pageSize]; page 2
// returns just allCerts[pageSize-1] again -- i.e. the LAST row of page 1
// reappears as the FIRST (and only) row of page 2, exactly like an
// offset-based query re-fetching a row that shifted position after a new row
// was inserted ahead of it. It also records the SortField/SortAscending
// query parameters Command actually received, so a test can confirm the
// companion mitigation (requesting a stable, deterministic sort) is applied,
// not just that the dedup safety net catches the symptom.
func certPaginatedSearchOverlapHandler(
	t *testing.T,
	allCerts []api.GetCertificateResponse,
	pfxB64 string,
	gotSortField, gotSortAscending *string,
) http.HandlerFunc {
	t.Helper()
	if len(allCerts) != certificatesOrphanSearchPageSize {
		t.Fatalf("test setup: certPaginatedSearchOverlapHandler expects exactly %d certs, got %d", certificatesOrphanSearchPageSize, len(allCerts))
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
			if gotSortField != nil {
				*gotSortField = r.URL.Query().Get("SortField")
			}
			if gotSortAscending != nil {
				*gotSortAscending = r.URL.Query().Get("SortAscending")
			}
			page, convErr := strconv.Atoi(r.URL.Query().Get("PageReturned"))
			if convErr != nil || page < 1 {
				page = 1
			}
			var pageCerts []api.GetCertificateResponse
			switch page {
			case 1:
				pageCerts = allCerts
			default:
				pageCerts = []api.GetCertificateResponse{allCerts[len(allCerts)-1]}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certsToSDKSearchJSON(t, pageCerts))
		case strings.Contains(r.URL.Path, "Enrollment/PFX"):
			t.Errorf("Enrollment/PFX reached the mock server -- the timeout RoundTripper should have intercepted it")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}
}

// TestUnitEnrollPFX_TimeoutRecovery_DuplicateCandidateAcrossPagesDoesNotTriggerAmbiguousMatch
// is the full end-to-end regression test, covering both halves
// of the fix together: (a) searchCertificatesForOrphanRecovery must request a
// stable, deterministic sort (SortField=CertId, with an explicit direction) so
// offset-based pagination is consistent under concurrent writes, and (b)
// findOrphanedCertificateMatch must dedup by certificate Id as defense in
// depth. Without either half, this reproduces exactly the "double-counted
// candidate causes a spurious ambiguous-match refusal" bug: the sole genuine
// orphan (the last row of page 1) reappears as the sole row of page 2, and a
// pre-fix implementation would see it as TWO candidates and refuse to adopt.
func TestUnitEnrollPFX_TimeoutRecovery_DuplicateCandidateAcrossPagesDoesNotTriggerAmbiguousMatch(t *testing.T) {
	const (
		commonName = "tf-unit-duplicate-across-pages.example.com"
		password   = "TestPassword123!"
	)

	leaf, leafKey := buildSelfSignedLeaf(t, commonName)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, password)
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	now := time.Now().UTC()
	var certs []api.GetCertificateResponse
	for i := 0; i < certificatesOrphanSearchPageSize-1; i++ {
		certs = append(certs, realisticOrphanCert(i+1, commonName, "WrongTemplate", now.Add(-48*time.Hour)))
	}
	genuine := realisticOrphanCert(999, commonName, "SomeTemplate", now)
	certs = append(certs, genuine) // last row of the full page-1 batch

	var enrollAttempts int
	var gotSortField, gotSortAscending string
	srv := httptest.NewTLSServer(
		certPaginatedSearchOverlapHandler(t, certs, pfxB64, &gotSortField, &gotSortAscending),
	)
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}
	plan := newMinimalPFXPlan(commonName, password)

	ctx := context.Background()
	result, diags := r.enrollPFXV2(ctx, plan)

	if diags.HasError() {
		t.Fatalf(
			"expected the duplicate-row-across-pages case (simulating a concurrent write during a multi-page "+
				"orphan search) to resolve to a single candidate, not an ambiguous-match refusal, got: %v", diags,
		)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}
	if result.CertificateId.Value != 999 {
		t.Errorf("result.CertificateId = %d, want 999", result.CertificateId.Value)
	}
	if enrollAttempts != 1 {
		t.Fatalf("expected exactly 1 enrollment attempt, got %d", enrollAttempts)
	}
	if gotSortField != "CertId" {
		t.Errorf(
			"searchCertificatesForOrphanRecovery did not request a stable SortField=CertId (got %q) -- without a "+
				"deterministic sort, offset-based pagination is not guaranteed consistent across pages under "+
				"concurrent writes",
			gotSortField,
		)
	}
	if gotSortAscending == "" {
		t.Error("expected an explicit SortAscending direction to be requested alongside SortField=CertId")
	}
}

// TestUnitSearchCertificatesForOrphanRecovery_UsesCommandValidSortField is a
// live-lab-discovered regression test (2026-08-16, against kfclab): a real
// Command instance validates the SortField query parameter against the
// /Certificates endpoint's own PQL-sortable field names, which do NOT
// include "Id" (Command's response body DOES call the field "Id", but the
// queryable/sortable name for it is "CertId") -- Command rejects "Id" with
// HTTP 400 "Invalid sort field: Id.". Every existing orphan-recovery unit
// test in this file used a permissive mock server that accepts ANY
// SortField value, so this 400 was invisible to the entire TestUnit* suite
// and was only caught by running the orphaned-PFX-recovery path against a
// live lab for the first time. This test's mock server reproduces Command's
// real validation behavior (reject anything but the known-valid field
// names) instead of accepting everything, so a future regression back to
// "Id" (or any other invalid field name) fails here without needing a live
// lab.
func TestUnitSearchCertificatesForOrphanRecovery_UsesCommandValidSortField(t *testing.T) {
	const commonName = "tf-unit-validates-sortfield.example.com"

	// Mirrors the exact set Command accepts for GET /Certificates?SortField=
	// on kfclab (confirmed live 2026-08-16): CertId, IssuedCN, IssuedDate,
	// IssuerDN, and "" (unset) all returned HTTP 200; "Id" and
	// "CertificateId" both returned HTTP 400.
	validSortFields := map[string]bool{
		"":           true,
		"CertId":     true,
		"IssuedCN":   true,
		"IssuedDate": true,
		"IssuerDN":   true,
	}

	orphan := realisticOrphanCert(1, commonName, "SomeTemplate", time.Now().UTC())
	searchBody := certsToSDKSearchJSON(t, []api.GetCertificateResponse{orphan})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "Certificates") {
			sortField := r.URL.Query().Get("SortField")
			if !validSortFields[sortField] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(fmt.Sprintf(
					`{"ErrorCode":"0xA011004A","Message":"Invalid sort field: %s."}`, sortField,
				)))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(searchBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	sdkAuth := &mockLeafAuth{
		client: srv.Client(),
		server: &auth_providers.Server{
			Host:          strings.TrimPrefix(srv.URL, "https://"),
			SkipTLSVerify: true,
		},
	}
	sdkClient := keyfactor.NewAPIClientWithAuth(sdkAuth)

	results, err := searchCertificatesForOrphanRecovery(context.Background(), sdkClient, commonName)
	if err != nil {
		t.Fatalf(
			"searchCertificatesForOrphanRecovery failed against a mock server that validates SortField the way "+
				"real Command does -- this means the hardcoded SortField value is invalid: %v", err,
		)
	}
	if len(results) != 1 || results[0].Id != orphan.Id {
		t.Fatalf("expected exactly 1 result with Id %d, got %+v", orphan.Id, results)
	}
}

// TestUnitKeyfactorCertificateResourceCreate_PFX_OrphanRecoveryWarningReachesResponseDiagnostics
// is the F3 regression test. It drives the FULL Create() method (not just
// enrollPFXV2's return value, which resource_keyfactor_certificate_enroll_timeout_test.go's
// earlier tests -- e.g. TestUnitEnrollPFX_TimeoutRecovery_WarningSurfacedInDiagnostics
// -- already cover, and which is exactly why the bug this test targets
// escaped notice) and asserts the orphan-adoption warning actually lands in
// response.Diagnostics.
//
// Before the fix, Create's PFX branch only appended enrollPFXV2's returned
// diagnostics inside an `if pfxErr.HasError()` guard. Diagnostics.HasError()
// is only true for SeverityError, so on a successful recovery (err == nil,
// diags containing only an AddWarning) that guard is never entered and the
// warning is silently dropped -- a real `terraform apply` would show a clean
// "Creation complete" with zero indication that a private-key-bearing
// certificate was heuristically adopted, defeating the entire point of that
// warning existing.
func TestUnitKeyfactorCertificateResourceCreate_PFX_OrphanRecoveryWarningReachesResponseDiagnostics(t *testing.T) {
	const (
		cn       = "tf-unit-create-warning-propagation.example.com"
		password = "TestPassword123!"
	)

	leaf, leafKey := buildSelfSignedLeaf(t, cn)
	pfxDER, err := pkcs12.Encode(rand.Reader, leafKey, leaf, nil, password)
	if err != nil {
		t.Fatalf("pkcs12.Encode: %v", err)
	}
	pfxB64 := base64.StdEncoding.EncodeToString(pfxDER)

	orphan := realisticOrphanCert(7777, cn, "SomeTemplate", time.Now().UTC())
	orphan.Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD"
	orphan.SerialNumber = "01"
	orphan.IssuerDN = "CN=Test Root CA"

	var enrollAttempts int
	srv := httptest.NewTLSServer(certSearchAndRecoverHandler(t, []api.GetCertificateResponse{orphan}, pfxB64))
	defer srv.Close()

	client, sdkClient := newTimeoutMockClient(t, srv, "Enrollment/PFX", &enrollAttempts)
	r := resourceCommandCertificate{p: provider{configured: true, client: client, sdkClient: sdkClient}}

	ctx := context.Background()
	schema, sDiags := resourceCommandCertificateType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	nullList := types.List{ElemType: types.StringType, Null: true}
	nullMap := types.Map{ElemType: types.StringType, Null: true}
	plan := CommandCertificate{
		CommonName:          types.String{Value: cn},
		CSR:                 types.String{Null: true},
		KeyPassword:         types.String{Value: password},
		CertificateTemplate: types.String{Value: "SomeTemplate"},
		EnrollmentPattern:   types.String{Null: true},
		CertificateFormat:   types.String{Null: true},
		DNSSANs:             nullList,
		IPSANs:              nullList,
		URISANs:             nullList,
		Metadata:            nullMap,
		CollectionId:        types.Int64{Value: 0},
		ExpiryWarningDays:   types.Int64{Null: true},
	}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}

	req := tfsdk.CreateResourceRequest{Plan: planObj}
	resp := &tfsdk.CreateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected Create to succeed (a warning, not an error) for a successful orphan recovery, got: %+v", resp.Diagnostics)
	}
	if enrollAttempts != 1 {
		t.Fatalf("expected exactly 1 enrollment attempt (no blind retry), got %d", enrollAttempts)
	}

	var found bool
	for _, w := range resp.Diagnostics.Warnings() {
		if strings.Contains(w.Detail(), fmt.Sprintf("%d", orphan.Id)) {
			found = true
		}
	}
	if !found {
		t.Fatalf(
			"expected Create's response.Diagnostics to carry the orphan-adoption warning naming certificate %d "+
				"-- this is the F3 bug: enrollPFXV2's warning-only diagnostics were dropped because Create only "+
				"appended them inside an `if pfxErr.HasError()` guard, and HasError() is false for a "+
				"warning-only Diagnostics. Got diagnostics: %+v",
			orphan.Id, resp.Diagnostics,
		)
	}
}
