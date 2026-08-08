package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
)

// ---------------------------------------------------------------------------
// Regression tests for GitHub issue #190:
//
// keyfactor_template_role_binding failed with "'Policies' cannot be empty"
// on Command 25.x. Command's PUT /Templates is a full-replace endpoint, and
// its server-side validation derives an internal "Policies" set from the
// template's TemplatePolicy.PrimaryKeyAlgorithms/AlternativeKeyAlgorithms.
// The provider's UpdateTemplateArg had no TemplatePolicy field at all (fixed
// upstream in keyfactor-go-client, see the vendored replace directive in
// go.mod), and even once the field existed, addAllowedRequesterToTemplate /
// removeRoleFromTemplate built their UpdateTemplateArg from scratch without
// carrying the freshly-fetched template's TemplatePolicy through -- silently
// clearing it on every binding change for any enrollment-pattern-linked
// template.
//
// These tests drive addAllowedRequesterToTemplate and removeRoleFromTemplate
// against a local httptest server standing in for Command, and assert that
// the PUT /Templates payload they send carries the TemplatePolicy returned
// by the preceding GET /Templates/{id} unchanged. This is deliberately a
// direct struct/wire-level test rather than a VCR cassette: recording a real
// cassette would require performing a mutating PUT against a live lab.
// ---------------------------------------------------------------------------

// mockTemplateAuthConfig implements api.AuthConfig, pointing the SDK client
// at a local httptest server instead of a real Command instance.
type mockTemplateAuthConfig struct {
	serverConfig *auth_providers.Server
	httpClient   *http.Client
}

func (m *mockTemplateAuthConfig) GetServerConfig() *auth_providers.Server { return m.serverConfig }
func (m *mockTemplateAuthConfig) GetHttpClient() (*http.Client, error)    { return m.httpClient, nil }
func (m *mockTemplateAuthConfig) Authenticate() error                     { return nil }
func (m *mockTemplateAuthConfig) GetCommandVersion() string               { return "25.5.0.0" }

func newTemplateTestClient(server *httptest.Server) *api.Client {
	auth := &mockTemplateAuthConfig{
		serverConfig: &auth_providers.Server{
			Host:          server.URL,
			APIPath:       "/KeyfactorAPI",
			SkipTLSVerify: true,
		},
		httpClient: server.Client(),
	}
	ctx := context.Background()
	return api.NewKeyfactorClientWithAuth(auth, &ctx)
}

// existingTemplatePolicy is the TemplatePolicy the fake Command server
// returns from GET /Templates/{id} -- standing in for a real template that
// is linked to an enrollment pattern and already has key-algorithm policy
// configured.
func existingTemplatePolicy() *api.TemplatePolicy {
	allowKeyReuse := true
	allowWildcards := false
	return &api.TemplatePolicy{
		TemplateId:     4,
		AllowKeyReuse:  &allowKeyReuse,
		AllowWildcards: &allowWildcards,
		PrimaryKeyAlgorithms: []api.TemplateKeyAlgorithm{
			{Name: "RSA", BitLengths: []int{2048, 3072, 4096}},
			{Name: "Ed25519", BitLengths: []int{255}},
		},
	}
}

// existingTemplateFieldSweep returns a fully-populated api.GetTemplateResponse
// standing in for a real template that has every representable field set --
// including KeyRetentionDays, which is the field whose omission from
// UpdateTemplateArg reproduced the live "In order to enable a retention
// policy on a template, the number of days to retain after expiration must
// be defined" error (dev-harness Gap C, extends issue #190).
func existingTemplateFieldSweep() api.GetTemplateResponse {
	return api.GetTemplateResponse{
		Id:                     4,
		CommonName:             "Test Template",
		TemplateName:           "TestTemplate",
		Oid:                    "1.2.3.4",
		KeySize:                "2048",
		KeyType:                "RSA",
		ForestRoot:             "example.com",
		FriendlyName:           "Test Template",
		KeyRetention:           "AfterExpiration",
		KeyRetentionDays:       30,
		KeyArchival:            true,
		AllowedEnrollmentTypes: 2,
		AllowedRequesters:      []string{"ExistingRole"},
		RFCEnforcement:         true,
		RequiresApproval:       true,
		EnrollmentFields: []api.TemplateEnrollmentFields{
			{Id: 1, Name: "Field1", DataType: 1},
		},
		MetadataFields: []api.TemplateMetadataFields{
			{Id: 2, MetadataId: 5, DefaultValue: "def"},
		},
		TemplateRegexes: []api.TemplateRegex{
			{TemplateId: 4, SubjectPart: "CN", RegEx: "^A"},
		},
		TemplatePolicy: existingTemplatePolicy(),
	}
}

// newTemplateRoleBindingTestServer returns an httptest server that answers
// GET Templates/{id} with a canned template (including TemplatePolicy) and
// captures the body of any PUT Templates/ request into *capturedPUTBody.
func newTemplateRoleBindingTestServer(t *testing.T, capturedPUTBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			resp := existingTemplateFieldSweep()
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode GET response: %v", err)
			}
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			*capturedPUTBody = body
			w.Header().Set("Content-Type", "application/json")
			// Echo back a minimal, decodable UpdateTemplateResponse.
			if err := json.NewEncoder(w).Encode(api.UpdateTemplateResponse{
				GetTemplateResponse: api.GetTemplateResponse{Id: 4},
			}); err != nil {
				t.Fatalf("failed to encode PUT response: %v", err)
			}
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// assertPUTBodyCarriesExistingPolicy decodes the captured PUT body and fails
// the test if TemplatePolicy is missing or doesn't match what the fake
// server's GET response returned.
func assertPUTBodyCarriesExistingPolicy(t *testing.T, body []byte) {
	t.Helper()

	if len(body) == 0 {
		t.Fatal("no PUT request was captured")
	}

	var onWire map[string]interface{}
	if err := json.Unmarshal(body, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}

	policyRaw, ok := onWire["TemplatePolicy"]
	if !ok || policyRaw == nil {
		t.Fatalf("PUT /Templates payload has no TemplatePolicy; the template's existing policy was dropped. Full payload: %s", body)
	}

	policy, ok := policyRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("TemplatePolicy on the wire is not an object: %v", policyRaw)
	}

	if allowKeyReuse, ok := policy["AllowKeyReuse"].(bool); !ok || !allowKeyReuse {
		t.Errorf("TemplatePolicy.AllowKeyReuse on the wire = %v, want true (preserved from GET response)", policy["AllowKeyReuse"])
	}

	primaryAlgos, ok := policy["PrimaryKeyAlgorithms"].([]interface{})
	if !ok || len(primaryAlgos) != 2 {
		t.Fatalf("TemplatePolicy.PrimaryKeyAlgorithms on the wire = %v, want 2 entries carried over from GET response", policy["PrimaryKeyAlgorithms"])
	}
}

// assertPUTBodyCarriesFullFieldSweep decodes the captured PUT body and fails
// the test if any field that existingTemplateFieldSweep's GET response
// populated is missing (or doesn't match) on the wire. This is the
// regression test for dev-harness Gap C (extends issue #190):
// addAllowedRequesterToTemplate/removeRoleFromTemplate previously built their
// UpdateTemplateArg from a fixed subset of fields, silently clearing
// everything else (CertificateCleanupEnabled/TimeAfterExpiration/
// KeyRetentionDays/etc, to the extent the SDK models them at all) on every
// role-binding update. KeyRetentionDays specifically reproduces the live
// error observed on a real lab: "In order to enable a retention policy on a
// template, the number of days to retain after expiration must be defined."
func assertPUTBodyCarriesFullFieldSweep(t *testing.T, body []byte) {
	t.Helper()

	if len(body) == 0 {
		t.Fatal("no PUT request was captured")
	}

	var onWire map[string]interface{}
	if err := json.Unmarshal(body, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}

	// The root regression: KeyRetentionDays was never carried forward at
	// all, which triggers Command's "the number of days to retain after
	// expiration must be defined" validation error whenever the template's
	// KeyRetention policy requires a day count.
	if days, ok := onWire["KeyRetentionDays"].(float64); !ok || int(days) != 30 {
		t.Errorf(
			"PUT /Templates payload KeyRetentionDays = %v, want 30 (carried over from GET response) -- "+
				"this reproduces the root bug: omitting KeyRetentionDays from the PUT while KeyRetention is "+
				"set triggers Command's \"In order to enable a retention policy on a template, the number of "+
				"days to retain after expiration must be defined\" error",
			onWire["KeyRetentionDays"],
		)
	}

	stringChecks := map[string]string{
		"Oid":          "1.2.3.4",
		"KeySize":      "2048",
		"KeyType":      "RSA",
		"ForestRoot":   "example.com",
		"KeyRetention": "AfterExpiration",
	}
	for field, want := range stringChecks {
		if got, _ := onWire[field].(string); got != want {
			t.Errorf("PUT /Templates payload %s = %v, want %q carried over from GET response", field, onWire[field], want)
		}
	}

	boolChecks := map[string]bool{
		"KeyArchival":      true,
		"RFCEnforcement":   true,
		"RequiresApproval": true,
	}
	for field, want := range boolChecks {
		if got, ok := onWire[field].(bool); !ok || got != want {
			t.Errorf("PUT /Templates payload %s = %v, want %v carried over from GET response", field, onWire[field], want)
		}
	}

	if allowedEnrollmentTypes, ok := onWire["AllowedEnrollmentTypes"].(float64); !ok || int(allowedEnrollmentTypes) != 2 {
		t.Errorf("PUT /Templates payload AllowedEnrollmentTypes = %v, want 2 carried over from GET response", onWire["AllowedEnrollmentTypes"])
	}

	listChecks := []string{"EnrollmentFields", "MetadataFields", "TemplateRegexes"}
	for _, field := range listChecks {
		raw, ok := onWire[field]
		if !ok || raw == nil {
			t.Errorf("PUT /Templates payload has no %s -- the template's existing value was dropped instead of carried forward", field)
			continue
		}
		list, ok := raw.([]interface{})
		if !ok || len(list) != 1 {
			t.Errorf("PUT /Templates payload %s = %v, want exactly 1 entry carried over from GET response", field, raw)
		}
	}

	// KeyUsage is a documented, deliberate exception: GetTemplateResponse
	// models it as an int (bitmask) but UpdateTemplateArg models it as a
	// *bool -- there is no lossless conversion, so it is intentionally left
	// nil/omitted rather than sent with a wrong value. Assert it stays that
	// way rather than silently regressing to "carried forward" behavior that
	// would send a nonsensical value.
	if _, present := onWire["KeyUsage"]; present {
		t.Errorf("PUT /Templates payload unexpectedly includes KeyUsage = %v -- this field has a type mismatch between GetTemplateResponse (int) and UpdateTemplateArg (*bool) and must stay omitted, not be sent", onWire["KeyUsage"])
	}
}

func TestUnitAddAllowedRequesterToTemplatePreservesTemplatePolicy(t *testing.T) {
	var putBody []byte
	srv := newTemplateRoleBindingTestServer(t, &putBody)
	defer srv.Close()

	client := newTemplateTestClient(srv)

	diags := addAllowedRequesterToTemplate(context.Background(), client, "NewRole", "4")
	if diags.HasError() {
		t.Fatalf("addAllowedRequesterToTemplate returned diagnostics: %v", diags)
	}

	assertPUTBodyCarriesExistingPolicy(t, putBody)
	assertPUTBodyCarriesFullFieldSweep(t, putBody)
}

func TestUnitRemoveRoleFromTemplatePreservesTemplatePolicy(t *testing.T) {
	var putBody []byte
	srv := newTemplateRoleBindingTestServer(t, &putBody)
	defer srv.Close()

	client := newTemplateTestClient(srv)

	diags := removeRoleFromTemplate(context.Background(), client, "ExistingRole", 4)
	if diags.HasError() {
		t.Fatalf("removeRoleFromTemplate returned diagnostics: %v", diags)
	}

	assertPUTBodyCarriesExistingPolicy(t, putBody)
	assertPUTBodyCarriesFullFieldSweep(t, putBody)
}
