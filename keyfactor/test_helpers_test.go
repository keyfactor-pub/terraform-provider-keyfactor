package keyfactor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	circlEd448 "github.com/cloudflare/circl/sign/ed448"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	sdkresource "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"go.mozilla.org/pkcs7"
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
// Checks KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME env var first, then discovers
// from the lab by calling GetSecurityIdentities(). NOTE: this returns an identity
// that ALREADY EXISTS in Keyfactor — use it for data source tests, not resource
// create tests.
func discoverSecurityIdentity(t *testing.T, client *api.Client) string {
	t.Helper()

	if accountName := os.Getenv("KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME"); accountName != "" {
		t.Logf("Using identity from KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME: %s", accountName)
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

// discoverApplication returns the name of an existing certificate store
// container/application in the lab. Checks KEYFACTOR_CERTIFICATE_STORE_CONTAINER_NAME1
// env var first, then discovers via the API. Returns "" if none are available
// (caller should skip or test without a container).
func discoverApplication(t *testing.T, client *api.Client) string {
	t.Helper()

	if name := os.Getenv("KEYFACTOR_CERTIFICATE_STORE_CONTAINER_NAME1"); name != "" {
		t.Logf("Using application/container name from env: %s", name)
		return name
	}

	containers, err := client.GetStoreContainers()
	if err != nil {
		t.Logf("Failed to list store containers for discovery: %s — tests will run without a container", err)
		return ""
	}

	if containers == nil || len(*containers) == 0 {
		t.Logf("No certificate store containers/applications available in the lab")
		return ""
	}

	for _, c := range *containers {
		t.Logf("Available application/container: %s (ID: %d, StoreType: %d)", c.Name, *c.Id, c.CertStoreType)
	}

	// Return the first one
	name := (*containers)[0].Name
	t.Logf("Discovered application/container: %s", name)
	return name
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

// requireActiveAgent skips the test with a warning if the best available agent
// has not checked in within the configured threshold (default 24h).
// Set KEYFACTOR_AGENT_MAX_STALE_HOURS to override.
func requireActiveAgent(t *testing.T, client *api.Client) {
	t.Helper()

	maxStaleHours := 24.0
	if v := os.Getenv("KEYFACTOR_AGENT_MAX_STALE_HOURS"); v != "" {
		if h, err := strconv.ParseFloat(v, 64); err == nil && h > 0 {
			maxStaleHours = h
		}
	}

	agents, err := client.GetAgentList()
	if err != nil {
		t.Skipf("WARN: could not list agents (%v) — skipping deploy test", err)
		return
	}

	// Find best agent (same preference as discoverAgent: approved first, then most recent LastSeen)
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Status != agents[j].Status {
			return agents[i].Status > agents[j].Status
		}
		return agents[i].LastSeen > agents[j].LastSeen
	})

	var best *api.Agent
	for i := range agents {
		if agents[i].Status == 2 {
			best = &agents[i]
			break
		}
	}
	if best == nil && len(agents) > 0 {
		best = &agents[0]
	}
	if best == nil {
		t.Skip("WARN: no orchestrator agents registered — skipping deploy test")
		return
	}

	lastSeen, err := time.Parse(time.RFC3339Nano, best.LastSeen)
	if err != nil {
		t.Logf("WARN: could not parse agent LastSeen %q (%v) — proceeding anyway", best.LastSeen, err)
		return
	}

	elapsed := time.Since(lastSeen)
	threshold := time.Duration(maxStaleHours * float64(time.Hour))
	if elapsed > threshold {
		t.Skipf("WARN: agent %s (machine: %s) last seen %.1f hours ago (threshold: %.0fh) — orchestrator appears offline, skipping deploy test",
			best.AgentId, best.ClientMachine, elapsed.Hours(), maxStaleHours)
	}
	t.Logf("Agent %s last seen %.1f minutes ago — proceeding", best.AgentId, elapsed.Minutes())
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

func (v *vcrAuthConfig) GetCommandVersion() string {
	// VCR tests always target a v25+ lab; use the Applications endpoint.
	return "25.1.0.0"
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
	// Use KEYFACTOR_API_PATH env var when set (e.g. during recording or CI replay).
	// Fall back to inferring from the first cassette URL otherwise.
	if envPath := os.Getenv("KEYFACTOR_API_PATH"); envPath != "" {
		return cassetteInfo{Host: u.Host, APIPath: strings.Trim(envPath, "/")}
	}

	// Infer API path from the URL. Known patterns:
	//   /Keyfactor/API/Enrollment/PFX → "Keyfactor/API"  (two-component prefix)
	//   /KeyfactorAPI/SSL/Certificates → "KeyfactorAPI"   (single-component prefix)
	// Only use two components when the path matches "Keyfactor/API".
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 3)
	apiPath := parts[0]
	if len(parts) >= 2 && strings.EqualFold(parts[0]+"/"+parts[1], "Keyfactor/API") {
		apiPath = parts[0] + "/" + parts[1]
	}
	return cassetteInfo{Host: u.Host, APIPath: apiPath}
}

// normalizeCassettePath strips the Keyfactor API path prefix from a URL path so that
// cassettes recorded on different labs (or with different apiPath settings) can be replayed.
// Uses KEYFACTOR_API_PATH env var when set; falls back to the two well-known defaults.
func normalizeCassettePath(p string) string {
	prefixes := []string{"/Keyfactor/API/", "/KeyfactorAPI/"}
	if envPath := os.Getenv("KEYFACTOR_API_PATH"); envPath != "" {
		prefixes = append([]string{"/" + strings.Trim(envPath, "/") + "/"}, prefixes...)
	}
	for _, prefix := range prefixes {
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
	ContainerName string `json:"container_name,omitempty"`
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
	CollectionId      int64  `json:"collection_id,omitempty"`
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
	TemplateName      string `json:"template_name"`
	CA                string `json:"ca"`
	CSRPem            string `json:"csr_pem"`
	EnrollmentPattern string `json:"enrollment_pattern,omitempty"`
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
// Security identity test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

type securityIdentityTestParams struct {
	// AccountName is the HCL-escaped account name (backslashes doubled, e.g. "DOMAIN\\\\user").
	AccountName string `json:"account_name"`
}

func writeSecurityIdentityTestParams(cassettePath string, params securityIdentityTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readSecurityIdentityTestParams(cassettePath string) securityIdentityTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return securityIdentityTestParams{}
	}
	var params securityIdentityTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return securityIdentityTestParams{}
	}
	return params
}

// ---------------------------------------------------------------------------
// PAM provider type test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

type pamProviderTypeTestParams struct {
	TypeName string `json:"type_name"`
}

func writePAMProviderTypeTestParams(cassettePath string, params pamProviderTypeTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readPAMProviderTypeTestParams(cassettePath string) pamProviderTypeTestParams {
	defaults := pamProviderTypeTestParams{
		TypeName: "tf-unit-pamtype",
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params pamProviderTypeTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// PAM provider test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

type pamProviderTestParams struct {
	TypeName string `json:"type_name"`
	ProvName string `json:"prov_name"`
}

func writePAMProviderTestParams(cassettePath string, params pamProviderTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readPAMProviderTestParams(cassettePath string) pamProviderTestParams {
	defaults := pamProviderTestParams{
		TypeName: "tf-unit-pamtype",
		ProvName: "tf-unit-pam",
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params pamProviderTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Application test params (cassette-recorded values for replay mode)
// ---------------------------------------------------------------------------

type applicationTestParams struct {
	AppName string `json:"app_name"`
}

func writeApplicationTestParams(cassettePath string, params applicationTestParams) {
	data, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readApplicationTestParams(cassettePath string) applicationTestParams {
	defaults := applicationTestParams{
		AppName: "tf-unit-app",
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params applicationTestParams
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
// Security role test params
// ---------------------------------------------------------------------------

type securityRoleTestParams struct {
	RoleName string `json:"role_name"`
}

func writeSecurityRoleTestParams(cassettePath string, params securityRoleTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readSecurityRoleTestParams(cassettePath string) securityRoleTestParams {
	defaults := securityRoleTestParams{RoleName: "tf-unit-role"}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params securityRoleTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Certificate store type test params
// ---------------------------------------------------------------------------

type certStoreTypeTestParams struct {
	Name      string `json:"name"`
	ShortName string `json:"short_name"`
}

func writeCertStoreTypeTestParams(cassettePath string, params certStoreTypeTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readCertStoreTypeTestParams(cassettePath string) certStoreTypeTestParams {
	defaults := certStoreTypeTestParams{Name: "tf-unit-store-type", ShortName: "TFUNIT"}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params certStoreTypeTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Certificate store types (plural) data source test params
// ---------------------------------------------------------------------------

type certStoreTypesDataSourceTestParams struct {
	StoreTypeCount  int    `json:"store_type_count"`
	FirstShortName  string `json:"first_short_name"`
	FirstCapability string `json:"first_capability"`
}

func writeCertStoreTypesDataSourceTestParams(cassettePath string, params certStoreTypesDataSourceTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readCertStoreTypesDataSourceTestParams(cassettePath string) certStoreTypesDataSourceTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return certStoreTypesDataSourceTestParams{}
	}
	var params certStoreTypesDataSourceTestParams
	if json.Unmarshal(data, &params) != nil {
		return certStoreTypesDataSourceTestParams{}
	}
	return params
}

// ---------------------------------------------------------------------------
// Agent data source test params
// ---------------------------------------------------------------------------

type agentDataSourceTestParams struct {
	AgentID       string `json:"agent_id"`
	ClientMachine string `json:"client_machine"`
}

func writeAgentDataSourceTestParams(cassettePath string, params agentDataSourceTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readAgentDataSourceTestParams(cassettePath string) agentDataSourceTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return agentDataSourceTestParams{}
	}
	var params agentDataSourceTestParams
	if json.Unmarshal(data, &params) != nil {
		return agentDataSourceTestParams{}
	}
	return params
}

// ---------------------------------------------------------------------------
// OAuth security claim test params
// ---------------------------------------------------------------------------

type oauthClaimRecordTestParams struct {
	ClaimValue string `json:"claim_value"`
	AuthScheme string `json:"auth_scheme"`
}

func writeOAuthClaimRecordTestParams(cassettePath string, params oauthClaimRecordTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readOAuthClaimRecordTestParams(cassettePath string) oauthClaimRecordTestParams {
	defaults := oauthClaimRecordTestParams{ClaimValue: "tf-unit-claim", AuthScheme: "System"}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params oauthClaimRecordTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// OAuth security role test params
// ---------------------------------------------------------------------------

type oauthRoleRecordTestParams struct {
	RoleName string `json:"role_name"`
}

func writeOAuthRoleRecordTestParams(cassettePath string, params oauthRoleRecordTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readOAuthRoleRecordTestParams(cassettePath string) oauthRoleRecordTestParams {
	defaults := oauthRoleRecordTestParams{RoleName: "tf-unit-oauth-role"}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params oauthRoleRecordTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// OAuth security role claim association test params
// ---------------------------------------------------------------------------

type oauthRoleClaimAssocTestParams struct {
	RoleName1  string `json:"role_name_1"`
	RoleName2  string `json:"role_name_2"`
	ClaimValue string `json:"claim_value"`
}

func writeOAuthRoleClaimAssocTestParams(cassettePath string, params oauthRoleClaimAssocTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readOAuthRoleClaimAssocTestParams(cassettePath string) oauthRoleClaimAssocTestParams {
	defaults := oauthRoleClaimAssocTestParams{
		RoleName1:  "tf-unit-role-assoc-1",
		RoleName2:  "tf-unit-role-assoc-2",
		ClaimValue: "tf-unit-claim-assoc",
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params oauthRoleClaimAssocTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Enrollment pattern data source test params
// ---------------------------------------------------------------------------

type enrollmentPatternTestParams struct {
	PatternName string `json:"pattern_name"`
}

func writeEnrollmentPatternTestParams(cassettePath string, params enrollmentPatternTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readEnrollmentPatternTestParams(cassettePath string) enrollmentPatternTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return enrollmentPatternTestParams{}
	}
	var params enrollmentPatternTestParams
	if json.Unmarshal(data, &params) != nil {
		return enrollmentPatternTestParams{}
	}
	return params
}

// ---------------------------------------------------------------------------
// CA test params
// ---------------------------------------------------------------------------

type caTestParams struct {
	CAName string `json:"ca_name"`
	CAID   string `json:"ca_id"`
	CAHost string `json:"ca_host"`
}

func writeCATestParams(cassettePath string, params caTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readCATestParams(cassettePath string) caTestParams {
	defaults := caTestParams{CAName: "Sub-CA", CAID: "1", CAHost: "localhost"}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params caTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Certificate template test params
// ---------------------------------------------------------------------------

type templateTestParams struct {
	TemplateName string `json:"template_name"`
	TemplateID   string `json:"template_id"`
}

func writeTemplateTestParams(cassettePath string, params templateTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readTemplateTestParams(cassettePath string) templateTestParams {
	defaults := templateTestParams{TemplateName: "WebServer", TemplateID: "1"}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params templateTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}

// ---------------------------------------------------------------------------
// Certificate deploy test params
// ---------------------------------------------------------------------------

type deployTestParams struct {
	CN                string `json:"cn"`
	StoreType         string `json:"store_type"`
	ClientMachine     string `json:"client_machine"`
	AgentID           string `json:"agent_id"`
	StorePath         string `json:"store_path"`
	CAName            string `json:"ca_name"`
	TemplateName      string `json:"template_name"`
	EnrollmentPattern string `json:"enrollment_pattern,omitempty"`
}

func writeDeployTestParams(cassettePath string, params deployTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readDeployTestParams(cassettePath string) deployTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return deployTestParams{}
	}
	var params deployTestParams
	if json.Unmarshal(data, &params) != nil {
		return deployTestParams{}
	}
	return params
}

// ---------------------------------------------------------------------------
// Template role binding test params
// ---------------------------------------------------------------------------

type roleBindingTestParams struct {
	RoleName     string `json:"role_name"`
	TemplateName string `json:"template_name"`
}

func writeRoleBindingTestParams(cassettePath string, params roleBindingTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readRoleBindingTestParams(cassettePath string) roleBindingTestParams {
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return roleBindingTestParams{}
	}
	var params roleBindingTestParams
	if json.Unmarshal(data, &params) != nil {
		return roleBindingTestParams{}
	}
	return params
}

// discoverRoleBinding finds a template in the lab that has at least one allowed
// requester role. Returns the first role name and the template's CommonName.
// Skips the test if no such binding exists in the lab.
func discoverRoleBinding(t *testing.T, client *api.Client) (roleName, templateName string) {
	t.Helper()
	templates, err := client.GetTemplates()
	if err != nil {
		t.Skipf("Skipping: could not fetch templates: %v", err)
	}
	for _, tmpl := range templates {
		if tmpl.UseAllowedRequesters && len(tmpl.AllowedRequesters) > 0 {
			return tmpl.AllowedRequesters[0], tmpl.CommonName
		}
	}
	t.Skip("Skipping: no template role bindings found in lab")
	return "", ""
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
			recorder.WithSkipRequestLatency(true),
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

// testAccCertPFXConfigEnrollmentPatternNoCA generates HCL for a PFX certificate
// resource test using an enrollment pattern without specifying certificate_authority.
// Command v25.5+ auto-selects the CA from CAs associated with the enrollment pattern.
func testAccCertPFXConfigEnrollmentPatternNoCA(enrollmentPattern, cn string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                      = "%s"
  certificate_enrollment_pattern   = "%s"
  key_password                     = "Tftest123456"
}
`, cn, enrollmentPattern)
}

// testAccCertPFXConfigTemplateOnly generates HCL for a PFX certificate resource
// test using only certificate_template (no enrollment pattern, no CA).
// On v25+ labs the provider auto-resolves the enrollment pattern from the template.
func testAccCertPFXConfigTemplateOnly(templateName, cn string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name          = "%s"
  certificate_template = "%s"
  key_password         = "Tftest123456"
}
`, cn, templateName)
}

// testAccCertCSRConfigEnrollmentPatternNoCA generates HCL for a CSR-based certificate
// resource test using an enrollment pattern without specifying certificate_authority.
// Command v25.5+ auto-selects the CA from CAs associated with the enrollment pattern.
func testAccCertCSRConfigEnrollmentPatternNoCA(enrollmentPattern, csr string) string {
	decodedCSR := strings.ReplaceAll(csr, `\n`, "\n")
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test_csr" {
  certificate_enrollment_pattern   = "%s"
  csr                              = <<-EOT
%s
EOT
}
`, enrollmentPattern, strings.TrimRight(decodedCSR, "\n"))
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

// certCollectionIdConfig generates HCL for a PFX certificate resource with an
// optional collection_id. Pass collectionId=0 to omit the field entirely.
func certCollectionIdConfig(enrollmentPattern, templateName, ca, cn string, collectionId int64) string {
	colLine := ""
	if collectionId != 0 {
		colLine = fmt.Sprintf("\n  collection_id          = %d", collectionId)
	}
	if enrollmentPattern != "" {
		return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                      = "%s"
  certificate_authority            = "%s"
  certificate_enrollment_pattern   = "%s"
  key_password                     = "Tftest123456"%s
}
`, cn, ca, enrollmentPattern, colLine)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name            = "%s"
  certificate_authority  = "%s"
  certificate_template   = "%s"
  key_password           = "Tftest123456"%s
}
`, cn, ca, templateName, colLine)
}

// parseCNFromCSRPEM extracts the CommonName from a PEM-encoded CSR.
// Returns "" if parsing fails, allowing callers to fall back gracefully.
func parseCNFromCSRPEM(csrPEM string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return ""
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return ""
	}
	return csr.Subject.CommonName
}

// labKeyTypePolicyErrorCheck returns a resource.TestCase ErrorCheck function that
// skips the test (rather than failing it) when the error indicates the lab's
// enrollment pattern does not support the requested key type or size.
//
// labKeyTypePolicyErrorCheck returns a resource.TestCase ErrorCheck function that
// propagates all errors unchanged. The *skip flag is available for callers that
// need to clean up partial cassette files in a t.Cleanup when a skip occurs
// through other means.
func labKeyTypePolicyErrorCheck(t *testing.T, caseName string, skip *bool) func(error) error {
	t.Helper()
	return func(err error) error {
		return err
	}
}

// testCheckCertPEMIsLeaf returns a TestCheckFunc that parses the PEM certificate
// stored in the named state attribute and asserts it is an end-entity (IsCA=false).
//
// Regression guard for the P7B chain-ordering bug: if DownloadCertificate returns
// the root CA cert as the leaf (certs[0] from a root-first P7B), IsCA will be true
// and this check will fail — even when subject.subject_common_name is unpopulated
// (e.g. enrollment-pattern certs).
func testCheckCertPEMIsLeaf(resourceName, attrName string) sdkresource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %q not found in state", resourceName)
		}
		pemStr, ok := rs.Primary.Attributes[attrName]
		if !ok || pemStr == "" {
			return fmt.Errorf("attribute %q not set or empty on %s", attrName, resourceName)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return fmt.Errorf("attribute %q on %s is not a valid PEM block", attrName, resourceName)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse certificate from %q on %s: %v", attrName, resourceName, err)
		}
		if cert.IsCA {
			return fmt.Errorf(
				"certificate in %q on %s is a CA cert (CN=%q IsCA=true); expected end-entity leaf cert — possible P7B chain ordering bug",
				attrName, resourceName, cert.Subject.CommonName,
			)
		}
		return nil
	}
}

// testCheckCertPEMCommonName returns a TestCheckFunc that parses the PEM certificate
// in the named state attribute and asserts its CN matches expectedCN.
func testCheckCertPEMCommonName(resourceName, attrName, expectedCN string) sdkresource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %q not found in state", resourceName)
		}
		pemStr, ok := rs.Primary.Attributes[attrName]
		if !ok || pemStr == "" {
			return fmt.Errorf("attribute %q not set or empty on %s", attrName, resourceName)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return fmt.Errorf("attribute %q on %s is not a valid PEM block", attrName, resourceName)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse certificate from %q on %s: %v", attrName, resourceName, err)
		}
		if cert.Subject.CommonName != expectedCN {
			return fmt.Errorf(
				"certificate CN in %q on %s = %q, want %q — possible P7B chain ordering bug",
				attrName, resourceName, cert.Subject.CommonName, expectedCN,
			)
		}
		return nil
	}
}

// testCheckCertPEMKeyType returns a TestCheckFunc that parses the PEM certificate
// in the named state attribute and asserts its public key algorithm and curve
// match the expected values. This provides ground-truth validation from the
// actual certificate bytes rather than from server metadata fields (which can
// silently return the wrong key type if the CA ignores the request).
//
// keyType is case-insensitive: "RSA", "ECC", "ECDSA", "Ed25519".
// curve is the friendly curve name ("P-256", "P-384", "P-521") and is only
// checked when keyType is ECC/ECDSA; pass "" to skip curve validation.
func testCheckCertPEMKeyType(resourceName, attrName, keyType, curve string) sdkresource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %q not found in state", resourceName)
		}
		pemStr, ok := rs.Primary.Attributes[attrName]
		if !ok || pemStr == "" {
			return fmt.Errorf("attribute %q not set or empty on %s", attrName, resourceName)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return fmt.Errorf("attribute %q on %s is not a valid PEM block", attrName, resourceName)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse certificate from %q on %s: %v", attrName, resourceName, err)
		}

		switch strings.ToUpper(keyType) {
		case "RSA":
			if cert.PublicKeyAlgorithm != x509.RSA {
				return fmt.Errorf("certificate %q on %s: expected RSA key, got %v",
					attrName, resourceName, cert.PublicKeyAlgorithm)
			}
		case "ECC", "ECDSA":
			if cert.PublicKeyAlgorithm != x509.ECDSA {
				return fmt.Errorf("certificate %q on %s: expected ECDSA/ECC key, got %v (key algorithm in cert = %v)",
					attrName, resourceName, cert.PublicKeyAlgorithm, cert.PublicKeyAlgorithm)
			}
			if curve != "" {
				ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					return fmt.Errorf("certificate %q on %s: ECDSA public key type assertion failed", attrName, resourceName)
				}
				var wantCurve elliptic.Curve
				switch curve {
				case "P-256":
					wantCurve = elliptic.P256()
				case "P-384":
					wantCurve = elliptic.P384()
				case "P-521":
					wantCurve = elliptic.P521()
				default:
					return fmt.Errorf("testCheckCertPEMKeyType: unknown curve %q", curve)
				}
				if ecKey.Curve != wantCurve {
					return fmt.Errorf("certificate %q on %s: expected curve %s, got %s",
						attrName, resourceName, wantCurve.Params().Name, ecKey.Curve.Params().Name)
				}
			}
		case "ED25519":
			if cert.PublicKeyAlgorithm != x509.Ed25519 {
				return fmt.Errorf("certificate %q on %s: expected Ed25519 key, got %v",
					attrName, resourceName, cert.PublicKeyAlgorithm)
			}
		case "ED448":
			// Go's x509 package reports Ed448 as UnknownPublicKeyAlgorithm.
			// Verify by inspecting the SubjectPublicKeyInfo OID directly.
			var spki struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			if _, spkiErr := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); spkiErr != nil {
				return fmt.Errorf("certificate %q on %s: failed to parse SPKI: %v", attrName, resourceName, spkiErr)
			}
			oidEd448 := asn1.ObjectIdentifier{1, 3, 101, 113}
			if !spki.Algorithm.Algorithm.Equal(oidEd448) {
				return fmt.Errorf("certificate %q on %s: expected Ed448 key (OID 1.3.101.113), got OID %v",
					attrName, resourceName, spki.Algorithm.Algorithm)
			}
		default:
			return fmt.Errorf("testCheckCertPEMKeyType: unsupported keyType %q", keyType)
		}
		return nil
	}
}

// generateRootFirstP7BCassette writes a fully synthetic VCR cassette for a CSR
// certificate resource test where the Certificates/Download endpoint returns a
// root-first P7B (CA cert first, end-entity second).
//
// This directly exercises the cert-chain ordering bug: DownloadCertificate
// returns certs[0] as the leaf, but for root-first P7Bs certs[0] is the issuing
// CA. testCheckCertPEMIsLeaf will FAIL against the buggy code and PASS after
// the fix.
//
// Returns the leaf CN so callers can configure the Terraform resource correctly.
func generateRootFirstP7BCassette(t *testing.T, cassettePath string) string {
	t.Helper()

	const certID = 9999
	const leafCN = "tf-unit-csr-p7bbug.example.com"

	// Generate CA and leaf certs.
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

	// Compute thumbprint and serial for use in mock responses.
	thumbSum := sha1.Sum(leafCert.Raw)
	thumbprint := strings.ToUpper(hex.EncodeToString(thumbSum[:]))
	serialNumber := strings.ToUpper(fmt.Sprintf("%X", leafCert.SerialNumber))
	issuerDN := "CN=Test Root CA"

	// Leaf cert PEM for enrollment response.
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	// Root-first P7B: CA first, leaf second — the bug trigger.
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

	// Build JSON response bodies.
	enrollBody, _ := json.Marshal(map[string]interface{}{
		"CertificateInformation": map[string]interface{}{
			"SerialNumber":       serialNumber,
			"IssuerDN":           issuerDN,
			"Thumbprint":         thumbprint,
			"KeyfactorID":        certID,
			"Certificates":       []string{leafPEM},
			"RequestDisposition": "ISSUED",
			"DispositionMessage": "",
		},
	})
	getCertBody, _ := json.Marshal(map[string]interface{}{
		"Id":               certID,
		"Thumbprint":       thumbprint,
		"SerialNumber":     serialNumber,
		"IssuedDN":         "CN=" + leafCN,
		"IssuedCN":         leafCN,
		"IssuerDN":         issuerDN,
		"NotBefore":        leafCert.NotBefore.UTC().Format(time.RFC3339),
		"NotAfter":         leafCert.NotAfter.UTC().Format(time.RFC3339),
		"IsCACertificate":  false,
		"HasPrivateKey":    false,
		"TemplateId":       0,
		"CertificateKeyId": 0,
		"Locations":        []interface{}{},
		"Metadata":         map[string]interface{}{},
	})
	recoverBody, _ := json.Marshal(map[string]string{
		"ErrorCode": "0xA0110002",
		"Message":   "No private key could be found for the given certificate.",
	})
	downloadBody, _ := json.Marshal(map[string]string{
		"Content": p7B64,
	})
	revokeBody, _ := json.Marshal(map[string]interface{}{
		"RevokedIds":     []int{certID},
		"SuspendedCerts": []interface{}{},
	})

	const host = "keyfactor.test"
	const baseURL = "https://keyfactor.test/KeyfactorAPI"
	jsonHeader := http.Header{"Content-Type": []string{"application/json"}}

	mkReq := func(method, rawURL string) cassette.Request {
		return cassette.Request{
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Host: host, Method: method, URL: rawURL,
			Headers: http.Header{},
		}
	}
	mkResp := func(code int, body string) cassette.Response {
		return cassette.Response{
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			ContentLength: int64(len(body)),
			Body:          body,
			Headers:       jsonHeader,
			Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Code:          code,
		}
	}

	certQueryURL := fmt.Sprintf(
		"%s/Certificates/%d?includeHasPrivateKey=true&includeLocations=true&includeMetadata=true",
		baseURL, certID,
	)

	// Read triplet (GET cert + Recover 404 + Download root-first P7B).
	// We emit three copies to cover:
	//   [0..2]  perpetual-diff check after step 1 (Create)
	//   [3..5]  step 2 RefreshState
	//   [6..8]  perpetual-diff check after step 2 (RefreshState)
	readTriplet := func(base int) []*cassette.Interaction {
		return []*cassette.Interaction{
			{ID: base, Request: mkReq("GET", certQueryURL), Response: mkResp(200, string(getCertBody))},
			{ID: base + 1, Request: mkReq("POST", baseURL+"/Certificates/Recover"), Response: mkResp(404, string(recoverBody))},
			{ID: base + 2, Request: mkReq("POST", baseURL+"/Certificates/Download"), Response: mkResp(200, string(downloadBody))},
		}
	}
	interactions := []*cassette.Interaction{
		{ID: 0, Request: mkReq("POST", baseURL+"/Enrollment/CSR"), Response: mkResp(200, string(enrollBody))},
	}
	for _, ri := range readTriplet(1) {
		interactions = append(interactions, ri)
	}
	for _, ri := range readTriplet(4) {
		interactions = append(interactions, ri)
	}
	for _, ri := range readTriplet(7) {
		interactions = append(interactions, ri)
	}
	interactions = append(interactions,
		&cassette.Interaction{ID: 10, Request: mkReq("POST", baseURL+"/Certificates/Revoke"), Response: mkResp(200, string(revokeBody))},
	)
	c := &cassette.Cassette{
		Version:      2,
		Interactions: interactions,
	}

	data, marshalErr := yaml.Marshal(c)
	if marshalErr != nil {
		t.Fatalf("marshal cassette: %v", marshalErr)
	}
	if writeErr := os.WriteFile(cassettePath+".yaml", data, 0600); writeErr != nil {
		t.Fatalf("write cassette file: %v", writeErr)
	}

	return leafCN
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

// generateEd448CSR creates a PEM-encoded certificate signing request using an
// Ed448 key pair.  Go's crypto/x509 package does not support Ed448, so the CSR
// DER is constructed manually per RFC 2986 / RFC 8410.
func generateEd448CSR(t *testing.T, cn string) string {
	t.Helper()

	oidEd448 := asn1.ObjectIdentifier{1, 3, 101, 113}

	pub, priv, err := circlEd448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generateEd448CSR: generate key: %v", err)
	}

	// Marshal the subject Name.
	rawSubject, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		t.Fatalf("generateEd448CSR: marshal subject: %v", err)
	}

	// SubjectPublicKeyInfo: AlgorithmIdentifier (no params) + BIT STRING key.
	type algID struct{ Algorithm asn1.ObjectIdentifier }
	type spkiT struct {
		Algorithm algID
		PublicKey asn1.BitString
	}
	spkiDER, err := asn1.Marshal(spkiT{
		Algorithm: algID{Algorithm: oidEd448},
		PublicKey: asn1.BitString{Bytes: []byte(pub), BitLength: len(pub) * 8},
	})
	if err != nil {
		t.Fatalf("generateEd448CSR: marshal SPKI: %v", err)
	}

	// CertificationRequestInfo (TBS).
	type tbsT struct {
		Version    int
		Subject    asn1.RawValue
		SPKI       asn1.RawValue
		Attributes asn1.RawValue `asn1:"tag:0,optional"`
	}
	tbsDER, err := asn1.Marshal(tbsT{
		Version:    0,
		Subject:    asn1.RawValue{FullBytes: rawSubject},
		SPKI:       asn1.RawValue{FullBytes: spkiDER},
		Attributes: asn1.RawValue{Tag: 0, Class: 2, IsCompound: true},
	})
	if err != nil {
		t.Fatalf("generateEd448CSR: marshal TBS: %v", err)
	}

	// Ed448 signs the full message with an empty context (RFC 8410 §6).
	sig := circlEd448.Sign(priv, tbsDER, "")

	// CertificationRequest = TBS + AlgorithmIdentifier + Signature.
	type csrT struct {
		TBS                asn1.RawValue
		SignatureAlgorithm algID
		Signature          asn1.BitString
	}
	csrDER, err := asn1.Marshal(csrT{
		TBS:                asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algID{Algorithm: oidEd448},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatalf("generateEd448CSR: marshal CSR: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// generateCSRWithKeyType creates a PEM-encoded CSR using the specified key type.
// keyType is one of "RSA", "ECC", "Ed25519", "Ed448". curve is used for ECC (e.g. "P-256", "P-384", "P-521").
// keySize controls RSA key size (0 defaults to 2048).
func generateCSRWithKeyType(t *testing.T, cn, keyType, curve string, keySize ...int) string {
	t.Helper()
	var signer crypto.Signer
	var err error
	switch strings.ToUpper(keyType) {
	case "RSA":
		bits := 2048
		if len(keySize) > 0 && keySize[0] > 0 {
			bits = keySize[0]
		}
		signer, err = rsa.GenerateKey(rand.Reader, bits)
	case "ECC":
		var c elliptic.Curve
		switch curve {
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			c = elliptic.P256()
		}
		signer, err = ecdsa.GenerateKey(c, rand.Reader)
	case "ED25519":
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case "ED448":
		// x509.CreateCertificateRequest doesn't support Ed448; delegate to a
		// helper that constructs the CSR DER manually.
		return generateEd448CSR(t, cn)
	default:
		t.Fatalf("generateCSRWithKeyType: unsupported key type %q", keyType)
	}
	if err != nil {
		t.Fatalf("generateCSRWithKeyType: generate %s key: %v", keyType, err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		t.Fatalf("generateCSRWithKeyType: create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// testAccCertPFXConfigWithKeyType generates HCL for a PFX certificate resource
// test that includes key_type, key_size (0 = omit), and/or curve ("" = omit).
func testAccCertPFXConfigWithKeyType(templateName, ca, cn, keyType string, keySize int, curve string) string {
	var extra string
	if keyType != "" {
		extra += fmt.Sprintf("\n  key_type              = \"%s\"", keyType)
	}
	if keySize > 0 {
		extra += fmt.Sprintf("\n  key_size              = %d", keySize)
	}
	if curve != "" {
		extra += fmt.Sprintf("\n  curve                 = \"%s\"", curve)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name            = "%s"
  certificate_authority  = "%s"
  certificate_template   = "%s"
  key_password           = "Tftest123456"%s
}
`, cn, ca, templateName, extra)
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

// testAccCertCSRConfigWithFormat generates HCL for a CSR-based certificate with an
// explicit certificate_format. Used in format-change tests for the no-private-key path.
func testAccCertCSRConfigWithFormat(enrollmentPattern, templateName, ca, csr, certFormat string) string {
	formatLine := ""
	if certFormat != "" {
		formatLine = fmt.Sprintf("\n  certificate_format             = \"%s\"", certFormat)
	}
	if enrollmentPattern != "" {
		// Enrollment pattern path uses a quoted string — CSR must be single-line.
		singleLine := strings.ReplaceAll(strings.ReplaceAll(csr, "\r\n", `\n`), "\n", `\n`)
		return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  certificate_authority            = "%s"
  certificate_enrollment_pattern   = "%s"
  csr                              = "%s"%s
}
`, ca, enrollmentPattern, singleLine, formatLine)
	}
	decodedCSR := strings.ReplaceAll(csr, `\n`, "\n")
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  certificate_authority  = "%s"
  certificate_template   = "%s"
  csr                    = <<-EOT
%s
EOT%s
}
`, ca, templateName, strings.TrimRight(decodedCSR, "\n"), formatLine)
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

		// K8SPKCS12 requires store_password and CertificateDataFieldName.
		storePasswordLine := ""
		certDataFieldLine := ""
		if stLower == "k8spkcs12" {
			storePasswordLine = `  store_password   = "Tftest123456"` + "\n"
			certDataFieldLine = `    CertificateDataFieldName = "pfx"` + "\n"
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
%s  properties = {
    KubeSecretType = "%s"
%s  }
}
`, clientMachine, storePath, agentID, storeType, creds, storePasswordLine, kubeSecretType, certDataFieldLine)
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

func testAccCertStoreConfigWithInventory(storeType, clientMachine, agentID, storePath string) string {
	stLower := strings.ToLower(storeType)
	if strings.HasPrefix(stLower, "k8s") {
		creds := k8sStoreCredentials()
		kubeSecretType := "tls"
		switch stLower {
		case "k8ssecret":
			kubeSecretType = "opaque"
		case "k8sjks":
			kubeSecretType = "jks"
		case "k8spkcs12":
			kubeSecretType = "pkcs12"
		}
		storePasswordLine := ""
		certDataFieldLine := ""
		if stLower == "k8spkcs12" {
			storePasswordLine = `  store_password     = "Tftest123456"` + "\n"
			certDataFieldLine = `    CertificateDataFieldName = "pfx"` + "\n"
		}
		return fmt.Sprintf(`
resource "keyfactor_certificate_store" "test" {
  client_machine     = "%s"
  store_path         = "%s"
  agent_identifier   = "%s"
  store_type         = "%s"
  server_username    = "kubeconfig"
  server_password    = <<EOT
%s
EOT
  server_use_ssl     = true
  inventory_schedule = "Daily at 12:00:00"
%s  properties = {
    KubeSecretType = "%s"
%s  }
}
`, clientMachine, storePath, agentID, storeType, creds, storePasswordLine, kubeSecretType, certDataFieldLine)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate_store" "test" {
  client_machine     = "%s"
  store_path         = "%s"
  agent_identifier   = "%s"
  store_type         = "%s"
  inventory_schedule = "Daily at 12:00:00"
}
`, clientMachine, storePath, agentID, storeType)
}

// testAccCertStoreConfigWithAppName generates HCL for a certificate store resource
// that uses application_name (the v25+ alias) instead of container_name.
// Pass appName="" to omit the application_name attribute.
func testAccCertStoreConfigWithAppName(storeType, clientMachine, agentID, storePath, appName string) string {
	stLower := strings.ToLower(storeType)
	appLine := ""
	if appName != "" {
		appLine = fmt.Sprintf("  application_name = %q\n", appName)
	}

	if strings.HasPrefix(stLower, "k8s") {
		creds := k8sStoreCredentials()
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
%s  server_username  = "kubeconfig"
  server_password  = <<EOT
%s
EOT
  server_use_ssl   = true
  properties = {
    KubeSecretType = "%s"
  }
}
`, clientMachine, storePath, agentID, storeType, appLine, creds, kubeSecretType)
	}

	return fmt.Sprintf(`
resource "keyfactor_certificate_store" "test" {
  client_machine   = "%s"
  store_path       = "%s"
  agent_identifier = "%s"
  store_type       = "%s"
%s}
`, clientMachine, storePath, agentID, storeType, appLine)
}

// testAccCertStoreConfigWithContainerName generates HCL for a certificate store resource
// that uses the legacy container_name attribute explicitly.
// Pass containerName="" to omit the container_name attribute.
func testAccCertStoreConfigWithContainerName(storeType, clientMachine, agentID, storePath, containerName string) string {
	stLower := strings.ToLower(storeType)
	containerLine := ""
	if containerName != "" {
		containerLine = fmt.Sprintf("  container_name = %q\n", containerName)
	}

	if strings.HasPrefix(stLower, "k8s") {
		creds := k8sStoreCredentials()
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
%s  server_username  = "kubeconfig"
  server_password  = <<EOT
%s
EOT
  server_use_ssl   = true
  properties = {
    KubeSecretType = "%s"
  }
}
`, clientMachine, storePath, agentID, storeType, containerLine, creds, kubeSecretType)
	}

	return fmt.Sprintf(`
resource "keyfactor_certificate_store" "test" {
  client_machine   = "%s"
  store_path       = "%s"
  agent_identifier = "%s"
  store_type       = "%s"
%s}
`, clientMachine, storePath, agentID, storeType, containerLine)
}

// testAccCertStoreDataSourceByID generates HCL for reading a cert store by
// client_machine + store_path using values from an existing resource reference.
func testAccCertStoreDataSourceByID(storeResourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_store" "test" {
  client_machine = %s.client_machine
  store_path     = %s.store_path
}
`, storeResourceRef, storeResourceRef)
}

// testAccCertStoreDataSourceByGUID generates HCL for reading a cert store by
// GUID (id) using the id from an existing resource reference.
func testAccCertStoreDataSourceByGUID(storeResourceRef string) string {
	return fmt.Sprintf(`
data "keyfactor_certificate_store" "test_by_guid" {
  id = %s.id
}
`, storeResourceRef)
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

// testAccCertDeployConfigWithAlias generates HCL for deploying a certificate to a store with an explicit alias.
// Required for store types like K8SPKCS12 where Command mandates an alias.
func testAccCertDeployConfigWithAlias(certResourceRef, storeResourceRef, alias string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate_deployment" "test" {
  certificate_id       = %s.identifier
  certificate_store_id = %s.id
  certificate_alias    = "%s"
}
`, certResourceRef, storeResourceRef, alias)
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

// ---------------------------------------------------------------------------
// Certificate SAN / full-subject HCL config helpers
// ---------------------------------------------------------------------------

// hclStringList formats a []string as a Terraform list literal, e.g. ["a", "b"].
func hclStringList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// genDNSSANs generates n DNS SANs like "san1.base.example.com".
func genDNSSANs(base string, n int) []string {
	sans := make([]string, n)
	for i := range sans {
		sans[i] = fmt.Sprintf("san%d.%s", i+1, base)
	}
	return sans
}

// genIPSANs generates n IP SANs in the 10.0.0.x range.
func genIPSANs(n int) []string {
	ips := make([]string, n)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}
	return ips
}

// genURISANs generates n URI SANs like "https://san1.base/path".
func genURISANs(base string, n int) []string {
	uris := make([]string, n)
	for i := range uris {
		uris[i] = fmt.Sprintf("https://san%d.%s/path", i+1, base)
	}
	return uris
}

// testAccCertPFXConfigWithSANs builds an HCL config for a PFX certificate
// with the given DNS, IP, and URI SANs (template-based enrollment).
func testAccCertPFXConfigWithSANs(templateName, ca, cn string, dnsSANs, ipSANs, uriSANs []string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name           = %q
  certificate_authority = %q
  certificate_template  = %q
  certificate_format    = "PEM"
  key_password          = "Tftest123456"
  dns_sans              = %s
  ip_sans               = %s
  uri_sans              = %s
}
`, cn, ca, templateName, hclStringList(dnsSANs), hclStringList(ipSANs), hclStringList(uriSANs))
}

// testAccCertPFXConfigEnrollmentPatternWithSANs builds an HCL config for a
// PFX certificate with the given SANs using enrollment-pattern enrollment.
func testAccCertPFXConfigEnrollmentPatternWithSANs(enrollmentPattern, ca, cn string, dnsSANs, ipSANs, uriSANs []string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name              = %q
  certificate_authority    = %q
  certificate_enrollment_pattern = %q
  certificate_format       = "PEM"
  key_password             = "Tftest123456"
  dns_sans                 = %s
  ip_sans                  = %s
  uri_sans                 = %s
}
`, cn, ca, enrollmentPattern, hclStringList(dnsSANs), hclStringList(ipSANs), hclStringList(uriSANs))
}

// testAccCertPFXConfigFullSubject builds an HCL config with all DN subject
// fields populated plus DNS and IP SANs (template-based enrollment).
func testAccCertPFXConfigFullSubject(templateName, ca, cn, locality, org, state, country, ou string, dnsSANs, ipSANs []string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name           = %q
  certificate_authority = %q
  certificate_template  = %q
  certificate_format    = "PEM"
  key_password          = "Tftest123456"
  locality              = %q
  organization          = %q
  state                 = %q
  country               = %q
  organizational_unit   = %q
  dns_sans              = %s
  ip_sans               = %s
}
`, cn, ca, templateName, locality, org, state, country, ou, hclStringList(dnsSANs), hclStringList(ipSANs))
}

// testAccCertPFXConfigEnrollmentPatternFullSubject builds an HCL config with
// all DN subject fields using enrollment-pattern enrollment.
func testAccCertPFXConfigEnrollmentPatternFullSubject(enrollmentPattern, ca, cn, locality, org, state, country, ou string, dnsSANs, ipSANs []string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name              = %q
  certificate_authority    = %q
  certificate_enrollment_pattern = %q
  certificate_format       = "PEM"
  key_password             = "Tftest123456"
  locality                 = %q
  organization             = %q
  state                    = %q
  country                  = %q
  organizational_unit      = %q
  dns_sans                 = %s
  ip_sans                  = %s
}
`, cn, ca, enrollmentPattern, locality, org, state, country, ou, hclStringList(dnsSANs), hclStringList(ipSANs))
}

// certSANConfig selects the correct HCL generator based on whether an
// enrollment pattern or a template name is provided.
func certSANConfig(enrollmentPattern, templateName, ca, cn string, dnsSANs, ipSANs, uriSANs []string) string {
	if enrollmentPattern != "" {
		return testAccCertPFXConfigEnrollmentPatternWithSANs(enrollmentPattern, ca, cn, dnsSANs, ipSANs, uriSANs)
	}
	return testAccCertPFXConfigWithSANs(templateName, ca, cn, dnsSANs, ipSANs, uriSANs)
}

// certFullSubjectConfig selects the correct HCL generator for full-subject
// configs based on whether an enrollment pattern is provided.
func certFullSubjectConfig(enrollmentPattern, templateName, ca, cn, locality, org, state, country, ou string, dnsSANs, ipSANs []string) string {
	if enrollmentPattern != "" {
		return testAccCertPFXConfigEnrollmentPatternFullSubject(enrollmentPattern, ca, cn, locality, org, state, country, ou, dnsSANs, ipSANs)
	}
	return testAccCertPFXConfigFullSubject(templateName, ca, cn, locality, org, state, country, ou, dnsSANs, ipSANs)
}

// ---------------------------------------------------------------------------
// Certificate metadata HCL config helpers
// ---------------------------------------------------------------------------

// hclMetadataMap formats a map[string]string as a Terraform map literal.
func hclMetadataMap(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteString("{\n")
	for k, v := range m {
		b.WriteString(fmt.Sprintf("    %q = %q\n", k, v))
	}
	b.WriteString("  }")
	return b.String()
}

// testAccCertPFXConfigWithMetadata builds HCL for a PEM certificate resource
// with the given metadata (template-based enrollment).
func testAccCertPFXConfigWithMetadata(templateName, ca, cn string, metadata map[string]string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name           = %q
  certificate_authority = %q
  certificate_template  = %q
  certificate_format    = "PEM"
  key_password          = "Tftest123456"
  metadata              = %s
}
`, cn, ca, templateName, hclMetadataMap(metadata))
}

// testAccCertPFXConfigEnrollmentPatternWithMetadata builds HCL for a PEM
// certificate resource with metadata using enrollment-pattern enrollment.
func testAccCertPFXConfigEnrollmentPatternWithMetadata(enrollmentPattern, ca, cn string, metadata map[string]string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                    = %q
  certificate_authority          = %q
  certificate_enrollment_pattern = %q
  certificate_format             = "PEM"
  key_password                   = "Tftest123456"
  metadata                       = %s
}
`, cn, ca, enrollmentPattern, hclMetadataMap(metadata))
}

// testAccCertPFXConfigEnrollmentPatternWithMetadataNoCA builds HCL for a PEM
// certificate resource with metadata using enrollment-pattern enrollment,
// without specifying certificate_authority.
func testAccCertPFXConfigEnrollmentPatternWithMetadataNoCA(enrollmentPattern, cn string, metadata map[string]string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                    = %q
  certificate_enrollment_pattern = %q
  certificate_format             = "PEM"
  key_password                   = "Tftest123456"
  metadata                       = %s
}
`, cn, enrollmentPattern, hclMetadataMap(metadata))
}

// testAccCertCSRConfigWithMetadata builds HCL for a CSR-based certificate
// resource with the given metadata.
func testAccCertCSRConfigWithMetadata(templateName, ca, csr string, metadata map[string]string) string {
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test_csr" {
  csr                   = %q
  certificate_authority = %q
  certificate_template  = %q
  metadata              = %s
}
`, csr, ca, templateName, hclMetadataMap(metadata))
}

// certMetadataConfig selects the correct enrollment-method HCL generator for
// metadata tests.
func certMetadataConfig(enrollmentPattern, templateName, ca, cn string, metadata map[string]string) string {
	if enrollmentPattern != "" {
		return testAccCertPFXConfigEnrollmentPatternWithMetadataNoCA(enrollmentPattern, cn, metadata)
	}
	return testAccCertPFXConfigWithMetadata(templateName, ca, cn, metadata)
}

// ---------------------------------------------------------------------------
// Key-type-specific params (cassette-recorded values for PFX + CSR key type tests)
// ---------------------------------------------------------------------------

// certPFXKeyTypeTestParams extends certPFXTestParams with the key type fields
// that should be used in the enrollment config. These are not auto-discovered —
// they are fixed by the test case — so only the lab-dependent fields are stored.
type certPFXKeyTypeTestParams struct {
	TemplateName      string `json:"template_name"`
	CA                string `json:"ca"`
	EnrollmentPattern string `json:"enrollment_pattern"`
	CN                string `json:"cn"`
	KeyType           string `json:"key_type"`
	KeySize           int    `json:"key_size"`
	Curve             string `json:"curve"`
}

func writeCertPFXKeyTypeTestParams(cassettePath string, params certPFXKeyTypeTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readCertPFXKeyTypeTestParams(cassettePath string, defaultKeyType string, defaultKeySize int, defaultCurve string) certPFXKeyTypeTestParams {
	defaults := certPFXKeyTypeTestParams{
		TemplateName: "2YearTestWebServer",
		CA:           "CommandCA1",
		CN:           "tf-unit-pfx.example.com",
		KeyType:      defaultKeyType,
		KeySize:      defaultKeySize,
		Curve:        defaultCurve,
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params certPFXKeyTypeTestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return defaults
	}
	// Preserve fixed-by-test values from defaults when not in params file.
	if params.KeyType == "" {
		params.KeyType = defaultKeyType
	}
	if params.KeySize == 0 {
		params.KeySize = defaultKeySize
	}
	if params.Curve == "" {
		params.Curve = defaultCurve
	}
	return params
}

// testAccCertPFXConfigWithKeyTypeAndPattern generates HCL for a PFX certificate
// resource test that includes key_type, key_size, and/or curve, using an
// enrollment_pattern instead of a template (required for Command v25+).
func testAccCertPFXConfigWithKeyTypeAndPattern(enrollmentPattern, ca, cn, keyType string, keySize int, curve string) string {
	var extra string
	if keyType != "" {
		extra += fmt.Sprintf("\n  key_type                      = \"%s\"", keyType)
	}
	if keySize > 0 {
		extra += fmt.Sprintf("\n  key_size                      = %d", keySize)
	}
	if curve != "" {
		extra += fmt.Sprintf("\n  curve                         = \"%s\"", curve)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                    = %q
  certificate_authority          = %q
  certificate_enrollment_pattern = %q
  key_password                   = "Tftest123456"%s
}
`, cn, ca, enrollmentPattern, extra)
}

// testAccCertPFXConfigWithKeyTypeAndPatternNoCA generates HCL for a PFX certificate
// resource test that includes key_type, key_size, and/or curve, using an
// enrollment_pattern without specifying certificate_authority.
// Command v25.5+ auto-selects the CA from CAs associated with the enrollment pattern.
func testAccCertPFXConfigWithKeyTypeAndPatternNoCA(enrollmentPattern, cn, keyType string, keySize int, curve string) string {
	var extra string
	if keyType != "" {
		extra += fmt.Sprintf("\n  key_type                      = \"%s\"", keyType)
	}
	if keySize > 0 {
		extra += fmt.Sprintf("\n  key_size                      = %d", keySize)
	}
	if curve != "" {
		extra += fmt.Sprintf("\n  curve                         = \"%s\"", curve)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test" {
  common_name                    = %q
  certificate_enrollment_pattern = %q
  key_password                   = "Tftest123456"%s
}
`, cn, enrollmentPattern, extra)
}

// testAccCertCSRConfigWithKeyType generates HCL for a CSR-based certificate test
// using a pre-generated CSR PEM. The key type is embedded in the CSR itself;
// this helper just formats the config.
func testAccCertCSRConfigWithKeyType(enrollmentPattern, templateName, ca, csrPem string) string {
	decodedCSR := strings.ReplaceAll(csrPem, `\n`, "\n")
	trimmedCSR := strings.TrimRight(decodedCSR, "\n")
	if enrollmentPattern != "" {
		return fmt.Sprintf(`
resource "keyfactor_certificate" "test_csr" {
  certificate_authority            = %q
  certificate_enrollment_pattern   = %q
  csr                              = <<-EOT
%s
EOT
}
`, ca, enrollmentPattern, trimmedCSR)
	}
	return fmt.Sprintf(`
resource "keyfactor_certificate" "test_csr" {
  certificate_authority  = %q
  certificate_template   = %q
  csr                    = <<-EOT
%s
EOT
}
`, ca, templateName, trimmedCSR)
}

// ---------------------------------------------------------------------------
// Certificate Collection helpers (direct REST calls — no client library support)
// ---------------------------------------------------------------------------

// buildCommandURL constructs a full URL for a Command API endpoint using the
// client's server config (host + API path).
func buildCommandURL(client *api.Client, endpoint string) (string, error) {
	serverConfig := client.AuthClient.GetServerConfig()
	if serverConfig == nil {
		return "", fmt.Errorf("nil server config on client")
	}
	u, err := url.Parse(serverConfig.Host)
	if err != nil {
		return "", fmt.Errorf("parse host %q: %w", serverConfig.Host, err)
	}
	if u.Scheme != "https" {
		u.Scheme = "https"
	}
	apiPath := serverConfig.APIPath
	if apiPath == "" {
		apiPath = "KeyfactorAPI"
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.Trim(apiPath, "/") + "/" + strings.TrimLeft(endpoint, "/")
	return u.String(), nil
}

// commandHTTPDo executes an HTTP request against the Command API, returning the
// response body bytes and the status code. It handles auth via the client's
// AuthClient.GetHttpClient().
func commandHTTPDo(client *api.Client, method, endpoint string, payload interface{}) ([]byte, int, error) {
	reqURL, err := buildCommandURL(client, endpoint)
	if err != nil {
		return nil, 0, err
	}

	var bodyReader io.Reader
	if payload != nil {
		jsonBytes, jErr := json.Marshal(payload)
		if jErr != nil {
			return nil, 0, fmt.Errorf("marshal payload: %w", jErr)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-keyfactor-api-version", "1")
	req.Header.Set("x-keyfactor-requested-with", "APIClient")

	httpClient, cErr := client.AuthClient.GetHttpClient()
	if cErr != nil {
		return nil, 0, fmt.Errorf("get http client: %w", cErr)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

// commandHTTPDoRaw executes an HTTP request against the Command API using a
// pre-marshalled body ([]byte).  queryParams is appended to the URL as a raw
// query string (e.g. "forceSave=true").  This differs from commandHTTPDo in two
// ways:
//  1. The body is sent verbatim — no re-marshalling through Go structs that
//     might drop unknown JSON fields (e.g. UseForEnrollment).
//  2. Query parameters are set via url.URL.RawQuery so they are never
//     percent-encoded into the path segment.
func commandHTTPDoRaw(client *api.Client, method, endpoint string, queryParams string, rawBody []byte) ([]byte, int, error) {
	reqURL, err := buildCommandURL(client, endpoint)
	if err != nil {
		return nil, 0, err
	}
	if queryParams != "" {
		// Parse and re-attach query params without touching the path.
		parsed, parseErr := url.Parse(reqURL)
		if parseErr != nil {
			return nil, 0, fmt.Errorf("parse URL: %w", parseErr)
		}
		parsed.RawQuery = queryParams
		reqURL = parsed.String()
	}

	var bodyReader io.Reader
	if rawBody != nil {
		bodyReader = bytes.NewReader(rawBody)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-keyfactor-api-version", "1")
	req.Header.Set("x-keyfactor-requested-with", "APIClient")

	httpClient, cErr := client.AuthClient.GetHttpClient()
	if cErr != nil {
		return nil, 0, fmt.Errorf("get http client: %w", cErr)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

// createTestCollection creates a certificate collection via the Command REST API
// and returns its integer ID. The collection uses a simple query that won't match
// most certificates (keeps it harmless).
func createTestCollection(t *testing.T, client *api.Client, name string) int {
	t.Helper()

	payload := map[string]interface{}{
		"Name":        name,
		"Description": "Auto-created by terraform-provider integration test",
		"Query":       fmt.Sprintf("CN -contains %q", name),
	}

	body, status, err := commandHTTPDo(client, "POST", "CertificateCollections", payload)
	if err != nil {
		t.Fatalf("createTestCollection: request failed: %s", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("createTestCollection: unexpected status %d: %s", status, string(body))
	}

	var result struct {
		Id int `json:"Id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("createTestCollection: decode response: %s (body: %s)", err, string(body))
	}
	if result.Id <= 0 {
		t.Fatalf("createTestCollection: got invalid collection ID %d (body: %s)", result.Id, string(body))
	}

	t.Logf("Created test certificate collection %q with ID %d", name, result.Id)
	return result.Id
}

// deleteTestCollection deletes a certificate collection by ID via the Command
// REST API. Errors are logged but do not fail the test (cleanup best-effort).
func deleteTestCollection(t *testing.T, client *api.Client, id int) {
	t.Helper()

	endpoint := fmt.Sprintf("CertificateCollections/%d", id)
	body, status, err := commandHTTPDo(client, "DELETE", endpoint, nil)
	if err != nil {
		t.Logf("deleteTestCollection: request failed (ID %d): %s", id, err)
		return
	}
	if status < 200 || status >= 300 {
		t.Logf("deleteTestCollection: unexpected status %d (ID %d): %s", status, id, string(body))
		return
	}
	t.Logf("Deleted test certificate collection ID %d", id)
}

// discoverOrCreateTestCollection returns a certificate collection ID for use in
// tests. If KEYFACTOR_CERTIFICATE_COLLECTION_ID is set, it uses that value.
// Otherwise it creates a new collection and registers a t.Cleanup to delete it.
func discoverOrCreateTestCollection(t *testing.T, client *api.Client) int {
	t.Helper()

	if idStr := os.Getenv("KEYFACTOR_CERTIFICATE_COLLECTION_ID"); idStr != "" {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			t.Fatalf("KEYFACTOR_CERTIFICATE_COLLECTION_ID must be an integer, got %q", idStr)
		}
		t.Logf("Using collection ID from env: %d", id)
		return id
	}

	name := fmt.Sprintf("tf-int-test-%d", time.Now().UnixNano())
	id := createTestCollection(t, client, name)
	t.Cleanup(func() {
		deleteTestCollection(t, client, id)
	})
	return id
}

// ---------------------------------------------------------------------------
// OAuth multi-claim association test params
// ---------------------------------------------------------------------------

type oauthMultiAssocTestParams struct {
	RoleName    string `json:"role_name"`
	ClaimValue1 string `json:"claim_value_1"`
	ClaimValue2 string `json:"claim_value_2"`
}

func writeOAuthMultiAssocTestParams(cassettePath string, params oauthMultiAssocTestParams) {
	data, _ := json.Marshal(params)
	_ = os.WriteFile(cassettePath+".params.json", data, 0600)
}

func readOAuthMultiAssocTestParams(cassettePath string) oauthMultiAssocTestParams {
	defaults := oauthMultiAssocTestParams{
		RoleName:    "tf-unit-role-multi-assoc",
		ClaimValue1: "tf-unit-claim-multi-1",
		ClaimValue2: "tf-unit-claim-multi-2",
	}
	data, err := os.ReadFile(cassettePath + ".params.json")
	if err != nil {
		return defaults
	}
	var params oauthMultiAssocTestParams
	if json.Unmarshal(data, &params) != nil {
		return defaults
	}
	return params
}
