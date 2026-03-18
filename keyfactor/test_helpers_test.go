package keyfactor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Precheck functions
// ---------------------------------------------------------------------------

// testAccPreCheck validates that required connection env vars are set.
// Calls t.Skip() with a helpful message if KEYFACTOR_HOSTNAME is not set.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYFACTOR_HOSTNAME") == "" {
		t.Skip("KEYFACTOR_HOSTNAME must be set for acceptance tests")
	}
}

// testAccIntegrationPreCheck validates connection env vars and creates a test
// client for resource discovery. Skips the test if no lab connection is available.
func testAccIntegrationPreCheck(t *testing.T) *api.Client {
	t.Helper()
	testAccPreCheck(t)

	client := newTestClient(t)
	return client
}

// ---------------------------------------------------------------------------
// Test client factory
// ---------------------------------------------------------------------------

// newTestClient creates an authenticated *api.Client using provider env vars.
// Skips the test if required env vars are missing or authentication fails.
func newTestClient(t *testing.T) *api.Client {
	t.Helper()

	hostname := os.Getenv("KEYFACTOR_HOSTNAME")
	if hostname == "" {
		t.Skip("KEYFACTOR_HOSTNAME must be set to create a test client")
	}

	serverConfig := &auth_providers.Server{
		Host:    hostname,
		APIPath: envOrDefault("KEYFACTOR_API_PATH", "KeyfactorAPI"),
	}

	// TLS settings
	if v := os.Getenv("KEYFACTOR_SKIP_VERIFY"); v == "true" || v == "1" {
		serverConfig.SkipTLSVerify = true
	}
	serverConfig.CACertPath = os.Getenv("KEYFACTOR_CA_CERT")

	// Determine auth type from env vars
	clientID := os.Getenv("KEYFACTOR_AUTH_CLIENT_ID")
	clientSecret := os.Getenv("KEYFACTOR_AUTH_CLIENT_SECRET")
	tokenURL := os.Getenv("KEYFACTOR_AUTH_TOKEN_URL")
	accessToken := os.Getenv("KEYFACTOR_AUTH_ACCESS_TOKEN")
	username := os.Getenv("KEYFACTOR_USERNAME")
	password := os.Getenv("KEYFACTOR_PASSWORD")

	if clientID != "" && clientSecret != "" && tokenURL != "" {
		serverConfig.ClientID = clientID
		serverConfig.ClientSecret = clientSecret
		serverConfig.OAuthTokenUrl = tokenURL
		serverConfig.Scopes = strings.Split(os.Getenv("KEYFACTOR_AUTH_SCOPES"), ",")
		serverConfig.Audience = os.Getenv("KEYFACTOR_AUTH_AUDIENCE")
	} else if accessToken != "" {
		serverConfig.AccessToken = accessToken
	} else if username != "" && password != "" {
		serverConfig.Username = username
		serverConfig.Password = password
		serverConfig.Domain = os.Getenv("KEYFACTOR_DOMAIN")
	} else {
		t.Skip("No valid auth credentials found in environment (need OAuth, access token, or basic auth)")
	}

	ctx := context.Background()
	client, err := api.NewKeyfactorClient(serverConfig, &ctx)
	if err != nil {
		t.Skipf("Failed to create test client (lab may be unavailable): %s", err)
	}

	return client
}

// ---------------------------------------------------------------------------
// Resource discovery helpers
// ---------------------------------------------------------------------------

// discoverTemplate returns a usable certificate template name.
// Checks KEYFACTOR_CERTIFICATE_TEMPLATE_NAME env var first, then discovers
// from the lab by calling GetTemplates().
func discoverTemplate(t *testing.T, client *api.Client) string {
	t.Helper()

	if name := os.Getenv("KEYFACTOR_CERTIFICATE_TEMPLATE_NAME"); name != "" {
		t.Logf("Using template from env: %s", name)
		return name
	}

	templates, err := client.GetTemplates()
	if err != nil {
		t.Fatalf("Failed to list templates for discovery: %s", err)
	}

	if len(templates) == 0 {
		t.Skip("No certificate templates available in the lab")
	}

	// Prefer templates that don't require approval
	for _, tmpl := range templates {
		if !tmpl.RequiresApproval && tmpl.CommonName != "" {
			t.Logf("Discovered template: %s (ID: %d)", tmpl.CommonName, tmpl.Id)
			return tmpl.CommonName
		}
	}

	// Fall back to first available
	t.Logf("Discovered template (fallback): %s (ID: %d)", templates[0].CommonName, templates[0].Id)
	return templates[0].CommonName
}

// discoverCA returns the certificate authority string for enrollment.
// Checks KEYFACTOR_CERTIFICATE_CA_DOMAIN + KEYFACTOR_CERTIFICATE_CA_NAME first,
// then discovers from the lab. Returns the full "domain\\name" or just "name".
func discoverCA(t *testing.T, client *api.Client) string {
	t.Helper()

	envDomain := os.Getenv("KEYFACTOR_CERTIFICATE_CA_DOMAIN")
	envName := os.Getenv("KEYFACTOR_CERTIFICATE_CA_NAME")
	if envDomain != "" && envName != "" {
		ca := fmt.Sprintf("%s\\\\%s", envDomain, envName)
		t.Logf("Using CA from env: %s", ca)
		return ca
	}

	cas, err := client.GetCAList()
	if err != nil {
		t.Fatalf("Failed to list CAs for discovery: %s", err)
	}

	if len(cas) == 0 {
		t.Skip("No certificate authorities available in the lab")
	}

	ca := cas[0]
	t.Logf("Discovered CA: %s (hostname: %s)", ca.LogicalName, ca.HostName)
	return ca.LogicalName
}

// discoverEnrollmentPattern returns an enrollment pattern name.
// Checks KEYFACTOR_ENROLLMENT_PATTERN env var first, then discovers from the lab.
// Prefers the "Default" pattern if present. Returns empty string if enrollment
// patterns are not available (pre-v25).
func discoverEnrollmentPattern(t *testing.T, client *api.Client) string {
	t.Helper()

	if name := os.Getenv("KEYFACTOR_ENROLLMENT_PATTERN"); name != "" {
		t.Logf("Using enrollment pattern from env: %s", name)
		return name
	}

	patterns, err := client.GetEnrollmentPatterns()
	if err != nil {
		// Enrollment patterns are only available in Command v25+
		t.Logf("Warning: Failed to list enrollment patterns (may require Command v25+): %s", err)
		return ""
	}

	if len(patterns) == 0 {
		t.Logf("Warning: No enrollment patterns available in the lab")
		return ""
	}

	// Prefer the "Default" pattern (case-insensitive match on name containing "default")
	for _, p := range patterns {
		if strings.EqualFold(p.Name, "Default Pattern") || strings.EqualFold(p.Name, "Default") {
			t.Logf("Discovered default enrollment pattern: %s (ID: %d)", p.Name, p.ID)
			return p.Name
		}
	}

	// Fall back to first pattern with TemplateDefault set
	for _, p := range patterns {
		if p.TemplateDefault {
			t.Logf("Discovered enrollment pattern (template default): %s (ID: %d)", p.Name, p.ID)
			return p.Name
		}
	}

	t.Logf("Discovered enrollment pattern: %s (ID: %d)", patterns[0].Name, patterns[0].ID)
	return patterns[0].Name
}

// discoverEnrollmentPatternTemplate returns the template short name associated
// with the given enrollment pattern. This is useful because the default enrollment
// pattern's template supports CSR enrollment even when other templates do not.
func discoverEnrollmentPatternTemplate(t *testing.T, client *api.Client, patternName string) string {
	t.Helper()

	patterns, err := client.GetEnrollmentPatterns()
	if err != nil {
		t.Fatalf("Failed to list enrollment patterns: %s", err)
	}

	for _, p := range patterns {
		if p.Name == patternName && p.Template != nil {
			name := p.Template.CommonName
			if name == "" {
				name = p.Template.TemplateName
			}
			t.Logf("Enrollment pattern %q uses template: %s (ID: %d)", patternName, name, p.Template.Id)
			return name
		}
	}

	t.Logf("Warning: Could not find template for enrollment pattern %q", patternName)
	return ""
}

// discoverSecurityIdentity returns an existing security identity's account name
// (in "DOMAIN\\user" format suitable for HCL with escaping).
// Checks KEYFACTOR_DOMAIN + KEYFACTOR_USERNAME env vars first, then discovers
// from the lab by calling GetSecurityIdentities().
func discoverSecurityIdentity(t *testing.T, client *api.Client) string {
	t.Helper()

	domain := os.Getenv("KEYFACTOR_DOMAIN")
	username := os.Getenv("KEYFACTOR_USERNAME")
	if domain != "" && username != "" {
		accountName := fmt.Sprintf("%s\\\\%s", domain, username)
		t.Logf("Using identity from env: %s", accountName)
		return accountName
	}

	identities, err := client.GetSecurityIdentities()
	if err != nil {
		t.Skipf("Failed to list security identities for discovery: %s", err)
	}

	if len(identities) == 0 {
		t.Skip("No security identities available in the lab")
	}

	// Pick a valid identity
	for _, id := range identities {
		if id.Valid && id.AccountName != "" {
			// The API returns "DOMAIN\user", we need "DOMAIN\\\\user" for HCL
			escaped := strings.ReplaceAll(id.AccountName, `\`, `\\`)
			t.Logf("Discovered security identity: %s (ID: %d, type: %s)", id.AccountName, id.Id, id.IdentityType)
			return escaped
		}
	}

	// Fall back to first
	escaped := strings.ReplaceAll(identities[0].AccountName, `\`, `\\`)
	t.Logf("Discovered identity (fallback): %s", identities[0].AccountName)
	return escaped
}

// discoverStoreTypeForAgent returns a store type short name that matches one of
// the given agent's capabilities. Falls back to discoverStoreType if no match found.
func discoverStoreTypeForAgent(t *testing.T, client *api.Client, agentID string) string {
	t.Helper()

	if name := os.Getenv("KEYFACTOR_CERTIFICATE_STORE_TYPE"); name != "" {
		t.Logf("Using store type from env: %s", name)
		return name
	}

	// Look up agent capabilities
	agents, err := client.GetAgentList()
	if err != nil {
		t.Logf("Warning: Failed to get agent list for capability check: %s", err)
		return discoverStoreType(t, client)
	}

	var capabilities []string
	for _, agent := range agents {
		if agent.AgentId == agentID {
			capabilities = agent.Capabilities
			break
		}
	}

	if len(capabilities) == 0 {
		t.Logf("Warning: Agent %s has no capabilities listed, falling back to store type discovery", agentID)
		return discoverStoreType(t, client)
	}

	t.Logf("Agent %s capabilities: %v", agentID, capabilities)

	// Cross-reference with available store types
	storeTypes, err := client.ListCertificateStoreTypes()
	if err != nil || storeTypes == nil || len(*storeTypes) == 0 {
		t.Logf("Warning: Could not list store types, using first capability: %s", capabilities[0])
		return capabilities[0]
	}

	// Find a store type whose short name matches an agent capability
	for _, cap := range capabilities {
		for _, st := range *storeTypes {
			if strings.EqualFold(st.ShortName, cap) {
				t.Logf("Matched store type %s (short: %s) with agent capability %s", st.Name, st.ShortName, cap)
				return st.ShortName
			}
		}
	}

	// Fall back to first capability
	t.Logf("No store type matched agent capabilities, using first capability: %s", capabilities[0])
	return capabilities[0]
}

// discoverExistingStore returns the details of an existing certificate store in the lab.
// This is useful for data source tests that need to read an existing store.
// Returns the store ID, client machine, store path, and store type short name.
func discoverExistingStore(t *testing.T, client *api.Client) (storeID, clientMachine, storePath, storeType string) {
	t.Helper()

	params := &map[string]interface{}{}
	stores, err := client.ListCertificateStores(params)
	if err != nil {
		t.Skipf("Failed to list certificate stores for discovery: %s", err)
	}

	if stores == nil || len(*stores) == 0 {
		t.Skip("No certificate stores available in the lab")
	}

	// Log all stores for debugging
	for _, s := range *stores {
		t.Logf("Available store: ID=%s, machine=%s, path=%s, type=%d, agentId=%s, approved=%v",
			s.Id, s.ClientMachine, s.StorePath, s.CertStoreType, s.AgentId, s.Approved)
	}

	store := (*stores)[0]
	// Look up the store type short name from the numeric type ID
	storeTypeShortName := discoverStoreTypeByID(t, client, store.CertStoreType)

	t.Logf("Discovered existing store: ID=%s, machine=%s, path=%s, type=%s",
		store.Id, store.ClientMachine, store.StorePath, storeTypeShortName)
	return store.Id, store.ClientMachine, store.StorePath, storeTypeShortName
}

// discoverStoreTypeByID returns the short name for a store type given its numeric ID.
func discoverStoreTypeByID(t *testing.T, client *api.Client, storeTypeID int) string {
	t.Helper()

	storeTypes, err := client.ListCertificateStoreTypes()
	if err != nil {
		t.Fatalf("Failed to list store types: %s", err)
	}

	if storeTypes != nil {
		for _, st := range *storeTypes {
			if st.StoreType == storeTypeID {
				return st.ShortName
			}
		}
	}

	return fmt.Sprintf("%d", storeTypeID)
}

// discoverOAuthAuthScheme returns an OAuth authentication scheme name.
// Checks KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME env var first.
// Falls back to "System" which is always present in OAuth-enabled Command instances.
func discoverOAuthAuthScheme(t *testing.T) string {
	t.Helper()

	if scheme := os.Getenv("KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME"); scheme != "" {
		t.Logf("Using OAuth auth scheme from env: %s", scheme)
		return scheme
	}

	// "System" is the built-in authentication scheme in Command OAuth installations
	t.Logf("Using default OAuth auth scheme: System")
	return "System"
}

// discoverStoreType returns a certificate store type short name.
// Checks KEYFACTOR_CERTIFICATE_STORE_TYPE env var first, then discovers from the lab.
func discoverStoreType(t *testing.T, client *api.Client) string {
	t.Helper()

	if name := os.Getenv("KEYFACTOR_CERTIFICATE_STORE_TYPE"); name != "" {
		t.Logf("Using store type from env: %s", name)
		return name
	}

	storeTypes, err := client.ListCertificateStoreTypes()
	if err != nil {
		t.Fatalf("Failed to list store types for discovery: %s", err)
	}

	if storeTypes == nil || len(*storeTypes) == 0 {
		t.Skip("No certificate store types available in the lab")
	}

	// Log all available store types for debugging
	for _, st := range *storeTypes {
		t.Logf("Available store type: %s (short: %s, ID: %d)", st.Name, st.ShortName, st.StoreType)
	}

	// Prefer K8S store types since they typically have active agents in the lab
	for _, st := range *storeTypes {
		shortLower := strings.ToLower(st.ShortName)
		if strings.Contains(shortLower, "k8s") || strings.Contains(shortLower, "kube") {
			t.Logf("Discovered K8S store type: %s (short: %s, ID: %d)", st.Name, st.ShortName, st.StoreType)
			return st.ShortName
		}
	}

	st := (*storeTypes)[0]
	t.Logf("Discovered store type (fallback): %s (short: %s, ID: %d)", st.Name, st.ShortName, st.StoreType)
	return st.ShortName
}

// discoverAgent returns the agent GUID and client machine name for an approved agent.
// Checks KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID first, then discovers.
func discoverAgent(t *testing.T, client *api.Client) (agentID, clientMachine string) {
	t.Helper()

	if id := os.Getenv("KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID"); id != "" {
		machine := os.Getenv("KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE")
		t.Logf("Using agent from env: %s (machine: %s)", id, machine)
		return id, machine
	}

	agents, err := client.GetAgentList()
	if err != nil {
		t.Fatalf("Failed to list agents for discovery: %s", err)
	}

	if len(agents) == 0 {
		t.Skip("No orchestrator agents available in the lab")
	}

	// Sort by status (prefer approved=2) then by most recent LastSeen
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Status != agents[j].Status {
			return agents[i].Status > agents[j].Status // higher status first
		}
		return agents[i].LastSeen > agents[j].LastSeen
	})

	// Pick first approved agent (Status == 2)
	for _, agent := range agents {
		if agent.Status == 2 {
			t.Logf("Discovered approved agent: %s (machine: %s, capabilities: %v)", agent.AgentId, agent.ClientMachine, agent.Capabilities)
			return agent.AgentId, agent.ClientMachine
		}
	}

	// Fall back to any agent
	agent := agents[0]
	t.Logf("Discovered agent (fallback, status=%d): %s (machine: %s, capabilities: %v)", agent.Status, agent.AgentId, agent.ClientMachine, agent.Capabilities)
	return agent.AgentId, agent.ClientMachine
}

// ---------------------------------------------------------------------------
// VCR Auth Wrapper for Unit Tests
// ---------------------------------------------------------------------------

// vcrAuthConfig implements the AuthConfig interface used by both the v3 Client
// and the SDK v24 clients. It returns an *http.Client with the VCR recorder
// transport injected, allowing tests to replay canned HTTP responses.
type vcrAuthConfig struct {
	httpClient *http.Client
	server     *auth_providers.Server
}

func (v *vcrAuthConfig) Authenticate() error {
	return nil
}

func (v *vcrAuthConfig) GetHttpClient() (*http.Client, error) {
	return v.httpClient, nil
}

func (v *vcrAuthConfig) GetServerConfig() *auth_providers.Server {
	return v.server
}

// newVCRServer returns a fake *auth_providers.Server suitable for VCR replay.
func newVCRServer(baseURL string) *auth_providers.Server {
	return &auth_providers.Server{
		Host:          baseURL,
		APIPath:       "KeyfactorAPI",
		Username:      "test-user",
		Password:      "test-pass",
		Domain:        "TEST",
		SkipTLSVerify: true,
	}
}

// cassetteInfo holds the recording host and API path extracted from a cassette file.
type cassetteInfo struct {
	Host    string
	APIPath string
}

// readCassetteInfo parses the cassette YAML to extract the host and API path
// from the first interaction's URL. Falls back to sensible defaults if parsing fails.
func readCassetteInfo(cassettePath string) cassetteInfo {
	data, err := os.ReadFile(cassettePath + ".yaml")
	if err != nil {
		return cassetteInfo{Host: "vcr.test.local", APIPath: "KeyfactorAPI"}
	}
	var c struct {
		Interactions []struct {
			Request struct {
				URL string `yaml:"url"`
			} `yaml:"request"`
		} `yaml:"interactions"`
	}
	if err := yaml.Unmarshal(data, &c); err != nil || len(c.Interactions) == 0 {
		return cassetteInfo{Host: "vcr.test.local", APIPath: "KeyfactorAPI"}
	}
	u, err := url.Parse(c.Interactions[0].Request.URL)
	if err != nil || u.Host == "" {
		return cassetteInfo{Host: "vcr.test.local", APIPath: "KeyfactorAPI"}
	}
	// API path is the leading path component(s) before the first real endpoint.
	// e.g. /Keyfactor/API/Enrollment/PFX → "Keyfactor/API"
	//      /KeyfactorAPI/SSL/Certificates → "KeyfactorAPI"
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 3)
	apiPath := parts[0]
	if len(parts) >= 2 {
		apiPath = parts[0] + "/" + parts[1]
	}
	return cassetteInfo{Host: u.Host, APIPath: apiPath}
}

// normalizeCassettePath strips known Keyfactor API path prefixes from a URL path so that
// cassettes recorded on different labs (or with different apiPath settings) can be replayed.
func normalizeCassettePath(p string) string {
	for _, prefix := range []string{"/Keyfactor/API/", "/KeyfactorAPI/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix)
		}
	}
	return strings.TrimPrefix(p, "/")
}

// makeVCRMatcher builds a cassette.MatcherFunc that matches only on HTTP
// method, normalised API path, and query string — ignoring host, headers,
// body, and protocol details. This is intentionally lenient so that cassettes
// recorded with real lab credentials can be replayed without any network or
// credentials.
func makeVCRMatcher() cassette.MatcherFunc {
	return func(r *http.Request, i cassette.Request) bool {
		if r.Method != i.Method {
			return false
		}
		iURL, err := url.Parse(i.URL)
		if err != nil {
			return false
		}
		if normalizeCassettePath(r.URL.Path) != normalizeCassettePath(iURL.Path) {
			return false
		}
		if r.URL.RawQuery != iURL.RawQuery {
			return false
		}
		return true
	}
}

// ---------------------------------------------------------------------------
// Certificate store test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

// storeTestParams holds the key field values used when recording a cassette,
// so that replay mode can use identical values and avoid Terraform plan drift.
type storeTestParams struct {
	StoreType     string `json:"store_type"`
	ClientMachine string `json:"client_machine"`
	AgentID       string `json:"agent_id"`
	StorePath     string `json:"store_path"`
}

// writeStoreTestParams saves recording parameters alongside the cassette file.
func writeStoreTestParams(cassettePath string, params storeTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

// readStoreTestParams loads recording parameters from the JSON params file.
// Returns safe defaults if the file does not exist yet.
func readStoreTestParams(cassettePath string) storeTestParams {
	defaults := storeTestParams{
		StoreType:     "K8STLSSecr",
		ClientMachine: "vcr-test-machine",
		AgentID:       "00000000-0000-0000-0000-000000000001",
		StorePath:     "default/tf-unit-test-1000000",
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params storeTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Certificate PFX test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

// certPFXTestParams holds the key field values used when recording a PFX cassette,
// so that replay mode can use identical values and avoid Terraform plan drift.
type certPFXTestParams struct {
	TemplateName      string `json:"template_name"`
	CA                string `json:"ca"`
	EnrollmentPattern string `json:"enrollment_pattern"`
	CN                string `json:"cn"`
}

func writeCertPFXTestParams(cassettePath string, params certPFXTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readCertPFXTestParams(cassettePath string) certPFXTestParams {
	defaults := certPFXTestParams{
		TemplateName: "2YearTestWebServer",
		CA:           "CommandCA1",
		CN:           "tf-unit-pfx.example.com",
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params certPFXTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Certificate CSR test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

// certCSRTestParams holds the key field values used when recording a CSR cassette.
// The CSRPem is stored so replay mode uses the exact same CSR that was enrolled,
// ensuring the cert still exists in the lab if needed (though VCR doesn't require it).
type certCSRTestParams struct {
	TemplateName string `json:"template_name"`
	CA           string `json:"ca"`
	CSRPem       string `json:"csr_pem"`
}

func writeCertCSRTestParams(cassettePath string, params certCSRTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readCertCSRTestParams(cassettePath string) certCSRTestParams {
	defaults := certCSRTestParams{
		TemplateName: "2YearTestWebServer",
		CA:           "CommandCA1",
		CSRPem:       "", // empty: will fall back to generating a dummy CSR in replay
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params certCSRTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Agents data source test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

type agentsTestParams struct {
	AgentCount int `json:"agent_count"`
}

func writeAgentsTestParams(cassettePath string, params agentsTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readAgentsTestParams(cassettePath string) agentsTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return agentsTestParams{}
	}
	var params agentsTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return agentsTestParams{}
	}
	return params
}

// ---------------------------------------------------------------------------
// Unique CN generator
// ---------------------------------------------------------------------------

// randomTestCN generates a unique common name for test certificates and CSRs.
// Uses Unix nanoseconds to avoid CN conflicts when tests run multiple times
// against the same lab without cleaning up previously-enrolled certificates.
func randomTestCN(prefix string) string {
	return fmt.Sprintf("%s-%d.example.com", prefix, time.Now().UnixNano()%1000000000)
}

// newVCRProviderFactories returns Terraform provider factories backed by a VCR
// recorder. In replay mode (default) it replays cassette files from
// keyfactor/testdata/cassettes/ and skips the test if none exist yet. Set
// RECORD_CASSETTES=1 to record new cassettes against a live lab.
//
// Usage:
//
//	factories, cleanup := newVCRProviderFactories(t, "my_cassette")
//	defer cleanup()
//	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, ...})
func newVCRProviderFactories(t *testing.T, cassetteName string) (map[string]func() (tfprotov6.ProviderServer, error), func()) {
	t.Helper()

	cassettePath := filepath.Join("testdata", "cassettes", cassetteName)
	matcher := makeVCRMatcher()

	if os.Getenv("RECORD_CASSETTES") != "1" {
		// Replay mode: pre-create the VCR recorder and inject it as testAuth so
		// provider.Configure() bypasses all auth/network logic entirely.
		info := readCassetteInfo(cassettePath)

		r, err := recorder.New(cassettePath,
			recorder.WithMode(recorder.ModeReplayOnly),
			recorder.WithMatcher(matcher),
		)
		if err != nil {
			t.Skipf("No cassette found for %q. Run with RECORD_CASSETTES=1 against a live lab to record.", cassetteName)
		}

		vcrAuth := &vcrAuthConfig{
			httpClient: r.GetDefaultClient(),
			server: &auth_providers.Server{
				Host:          info.Host,
				APIPath:       info.APIPath,
				Username:      "vcr-test-user",
				Password:      "Vcrtestpass1!",
				SkipTLSVerify: true,
			},
		}

		p := &provider{testAuth: vcrAuth}
		factories := map[string]func() (tfprotov6.ProviderServer, error){
			"keyfactor": providerserver.NewProtocol6WithError(p),
		}
		cleanup := func() {
			if stopErr := r.Stop(); stopErr != nil {
				t.Logf("Warning: VCR recorder stop error: %s", stopErr)
			}
		}
		return factories, cleanup
	}

	// Recording mode: create ONE shared VCR recorder for the entire test so
	// that ALL provider API calls (across multiple Configure() invocations) are
	// captured in a single cassette. We use testAuth to bypass Configure()'s
	// own auth/network logic and route every call through the VCR recorder.
	testAccPreCheck(t)
	realClient := newTestClient(t)
	realHTTPClient, hErr := realClient.AuthClient.GetHttpClient()
	if hErr != nil || realHTTPClient == nil {
		t.Fatalf("VCR recording: failed to get real HTTP client: %v", hErr)
	}

	r, rErr := recorder.New(cassettePath,
		recorder.WithMode(recorder.ModeRecordOnly),
		recorder.WithRealTransport(realHTTPClient.Transport),
		recorder.WithMatcher(matcher),
		// Redact auth and sensitive fields before saving cassette.
		recorder.WithHook(func(i *cassette.Interaction) error {
			delete(i.Request.Headers, "Authorization")
			// Redact ServerPassword from request bodies (may contain kubeconfig).
			if i.Request.Body != "" {
				var body map[string]interface{}
				if json.Unmarshal([]byte(i.Request.Body), &body) == nil {
					redacted := false
					for _, key := range []string{"ServerPassword", "Password"} {
						if v, ok := body[key]; ok && v != nil && v != "" {
							body[key] = "[REDACTED]"
							redacted = true
						}
					}
					if redacted {
						if sanitized, mErr := json.Marshal(body); mErr == nil {
							i.Request.Body = string(sanitized)
							i.Request.ContentLength = int64(len(sanitized))
						}
					}
				}
			}
			return nil
		}, recorder.BeforeSaveHook),
	)
	if rErr != nil {
		t.Fatalf("Failed to create VCR recorder for %q: %s", cassetteName, rErr)
	}

	vcrAuth := &vcrAuthConfig{
		httpClient: r.GetDefaultClient(),
		server:     realClient.AuthClient.GetServerConfig(),
	}
	p := &provider{testAuth: vcrAuth}
	factories := map[string]func() (tfprotov6.ProviderServer, error){
		"keyfactor": providerserver.NewProtocol6WithError(p),
	}
	cleanup := func() {
		if stopErr := r.Stop(); stopErr != nil {
			t.Logf("Warning: VCR recorder stop error: %s", stopErr)
		}
	}
	return factories, cleanup
}

// ---------------------------------------------------------------------------
// HCL config generators for integration tests
// ---------------------------------------------------------------------------

// testAccCertPFXConfig generates HCL for a PFX certificate resource test.
// cn is the common name to use; pass randomTestCN("tf-int-pfx") for unique values.
func testAccCertPFXConfig(templateName, ca, cn string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name            = "%s"
  certificate_authority  = "%s"
  certificate_template   = "%s"
  key_password           = "Tftest123456"
  dns_sans               = ["%s"]
}
`, cn, ca, templateName, cn)
}

// testAccCertPFXConfigWithFormat generates HCL for a PFX certificate resource
// test with an explicit certificate_format.
func testAccCertPFXConfigWithFormat(templateName, ca, cn, certFormat string) string {
	formatLine := ""
	if certFormat != "" {
		formatLine = fmt.Sprintf("\n  certificate_format    = \"%s\"", certFormat)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name            = "%s"
  certificate_authority  = "%s"
  certificate_template   = "%s"
  key_password           = "Tftest123456"
  dns_sans               = ["%s"]%s
}
`, cn, ca, templateName, cn, formatLine)
}

// testAccCertPFXConfigEnrollmentPattern generates HCL for a PFX certificate
// resource test using an enrollment pattern (required for Command v25+).
// cn is the common name to use; pass randomTestCN("tf-int-pfx") for unique values.
func testAccCertPFXConfigEnrollmentPattern(enrollmentPattern, ca, cn string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                      = "%s"
  certificate_authority            = "%s"
  certificate_enrollment_pattern   = "%s"
  key_password                     = "Tftest123456"
}
`, cn, ca, enrollmentPattern)
}

// testAccCertPFXConfigEnrollmentPatternWithFormat generates HCL for a PFX certificate
// resource test using an enrollment pattern with an explicit certificate_format.
func testAccCertPFXConfigEnrollmentPatternWithFormat(enrollmentPattern, ca, cn, certFormat string) string {
	formatLine := ""
	if certFormat != "" {
		formatLine = fmt.Sprintf("\n  certificate_format             = \"%s\"", certFormat)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                      = "%s"
  certificate_authority            = "%s"
  certificate_enrollment_pattern   = "%s"
  key_password                     = "Tftest123456"%s
}
`, cn, ca, enrollmentPattern, formatLine)
}

// testAccCertPFXConfigBothTemplateAndPattern generates HCL for a PFX certificate
// resource test that sets BOTH certificate_template and certificate_enrollment_pattern.
// This tests that the provider allows both to be specified simultaneously (fixes #146).
func testAccCertPFXConfigBothTemplateAndPattern(templateName, enrollmentPattern, ca, cn string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                      = "%s"
  certificate_authority            = "%s"
  certificate_template             = "%s"
  certificate_enrollment_pattern   = "%s"
  key_password                     = "Tftest123456"
}
`, cn, ca, templateName, enrollmentPattern)
}

// generateSimpleCSR creates a fresh PEM-encoded CSR with only a CN field.
// This avoids template subject field restrictions (e.g., "Wrong number of LOCALITY fields").
func generateSimpleCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %s", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(csrPEM)
}

// testAccCertCSRConfig generates HCL for a CSR-based certificate resource test.
func testAccCertCSRConfig(templateName, ca, csr string) string {
	// Decode literal \n escape sequences to real newlines so the HCL heredoc is valid.
	decodedCSR := strings.ReplaceAll(csr, `\n`, "\n")
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test_csr" {
  certificate_authority  = "%s"
  certificate_template   = "%s"
  csr                    = <<-EOT
%s
EOT
}
`, ca, templateName, strings.TrimRight(decodedCSR, "\n"))
}

// testAccCertCSRConfigEnrollmentPattern generates HCL for a CSR-based certificate
// resource test using an enrollment pattern (required for Command v25+).
func testAccCertCSRConfigEnrollmentPattern(enrollmentPattern, ca, csr string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test_csr" {
  certificate_authority            = "%s"
  certificate_enrollment_pattern   = "%s"
  csr                              = "%s"
}
`, ca, enrollmentPattern, csr)
}

// testAccCertDataSourceByID generates HCL for reading a certificate by Keyfactor ID
func testAccCertDataSourceByID(certResourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate" "test" {
  identifier    = %s.identifier
  key_password  = "Tftest123456"
}
`, certResourceRef)
}

// k8sStoreCredentials returns the kubeconfig JSON for K8S store server_password.
// Checks KEYFACTOR_K8S_CREDENTIALS_FILE (file path) then KEYFACTOR_K8S_SERVER_PASSWORD (raw content).
// Returns empty string if neither is set.
func k8sStoreCredentials() string {
	if filePath := os.Getenv("KEYFACTOR_K8S_CREDENTIALS_FILE"); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err == nil {
			return string(data)
		}
	}
	return os.Getenv("KEYFACTOR_K8S_SERVER_PASSWORD")
}

// testAccCertStoreConfig generates HCL for a certificate store resource test.
// Includes required credentials and properties for K8S store types.
func testAccCertStoreConfig(storeType, clientMachine, agentID, storePath string) string {
	stLower := strings.ToLower(storeType)
	if strings.HasPrefix(stLower, "k8s") {
		creds := k8sStoreCredentials()

		// Determine KubeSecretType based on store type
		kubeSecretType := "tls"
		switch stLower {
		case "k8ssecret":
			kubeSecretType = "opaque"
		case "k8sjks":
			kubeSecretType = "jks"
		case "k8spkcs12":
			kubeSecretType = "pkcs12"
		}

		return fmt.Sprintf(`
resource "keyfactor_certificate_store" "test" {
  client_machine   = "%s"
  store_path       = "%s"
  agent_identifier = "%s"
  store_type       = "%s"
  server_username  = "kubeconfig"
  server_password  = <<EOT
%s
EOT
  server_use_ssl   = true
  properties = {
    KubeSecretType = "%s"
  }
}
`, clientMachine, storePath, agentID, storeType, creds, kubeSecretType)
	}

	return fmt.Sprintf(`
resource "keyfactor_certificate_store" "test" {
  client_machine   = "%s"
  store_path       = "%s"
  agent_identifier = "%s"
  store_type       = "%s"
}
`, clientMachine, storePath, agentID, storeType)
}

// testAccCertStoreDataSourceByID generates HCL for reading a cert store by ID
func testAccCertStoreDataSourceByID(storeResourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_store" "test" {
  client_machine = %s.client_machine
  store_path     = %s.store_path
}
`, storeResourceRef, storeResourceRef)
}

// testAccAgentDataSourceConfig generates HCL for reading an agent by identifier (GUID or machine name)
func testAccAgentDataSourceConfig(identifier string) string {
	return fmt.Sprintf(`
data "keyfactor_agent" "test" {
  agent_identifier = "%s"
}
`, identifier)
}

// testAccEnrollmentPatternDataSourceConfig generates HCL for reading an enrollment pattern by name or ID
func testAccEnrollmentPatternDataSourceConfig(identifier string) string {
	return fmt.Sprintf(`
data "keyfactor_enrollment_pattern" "test" {
  identifier = "%s"
}
`, identifier)
}

// testAccCertDeployConfig generates HCL for deploying a certificate to a store.
// certResourceRef and storeResourceRef are Terraform resource references (e.g. "keyfactor_certificate.test").
func testAccCertDeployConfig(certResourceRef, storeResourceRef string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_deployment" "test" {
  certificate_id       = %s.identifier
  certificate_store_id = %s.id
}
`, certResourceRef, storeResourceRef)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
