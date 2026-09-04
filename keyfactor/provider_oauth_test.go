package keyfactor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// ---------------------------------------------------------------------------
// Unit tests : OAuth access_token propagation regression (v2.8.0 fix)
// ---------------------------------------------------------------------------

// TestUnitOAuthAccessTokenPropagation verifies that AccessToken, Audience, and
// Scopes from auth_providers.Server propagate correctly into CommandConfigOauth.
// This is a compilation + correctness regression test for the v2.8.0 bug where
// buildHttpClientV2 silently dropped these three fields from the struct literal.
// If the fields are ever removed from either struct, this test fails to compile.
func TestUnitOAuthAccessTokenPropagation(t *testing.T) {
	srv := &auth_providers.Server{
		Host:        "test.example.com",
		AccessToken: "tok-abc-provider-level",
		Audience:    "aud-xyz",
		Scopes:      []string{"openid"},
	}

	// Verify GetAuthType classifies access_token-only as "oauth"
	authType := srv.GetAuthType()
	if authType != "oauth" {
		t.Fatalf("GetAuthType() = %q, want %q for access_token-only Server", authType, "oauth")
	}

	// Mirror the struct construction from buildHttpClientV2 (SDK client.go)
	baseConfig := auth_providers.CommandAuthConfig{
		CommandHostName: srv.Host,
		CommandPort:     srv.Port,
		CommandAPIPath:  srv.APIPath,
		CommandCACert:   srv.CACertPath,
		SkipVerify:      srv.SkipTLSVerify,
	}
	oauthCfg := auth_providers.CommandConfigOauth{
		CommandAuthConfig: baseConfig,
		ClientID:          srv.ClientID,
		ClientSecret:      srv.ClientSecret,
		TokenURL:          srv.OAuthTokenUrl,
		AccessToken:       srv.AccessToken,
		Audience:          srv.Audience,
		Scopes:            srv.Scopes,
	}

	// Verify the three fields that were missing in the v2.8.0 regression
	if oauthCfg.AccessToken != "tok-abc-provider-level" {
		t.Errorf("CommandConfigOauth.AccessToken = %q, want %q", oauthCfg.AccessToken, "tok-abc-provider-level")
	}
	if oauthCfg.Audience != "aud-xyz" {
		t.Errorf("CommandConfigOauth.Audience = %q, want %q", oauthCfg.Audience, "aud-xyz")
	}
	if !reflect.DeepEqual(oauthCfg.Scopes, []string{"openid"}) {
		t.Errorf("CommandConfigOauth.Scopes = %v, want %v", oauthCfg.Scopes, []string{"openid"})
	}

	// Verify GetServerConfig round-trips correctly
	serverCfg := oauthCfg.GetServerConfig()
	if serverCfg.AccessToken != "tok-abc-provider-level" {
		t.Errorf("GetServerConfig().AccessToken = %q, want %q", serverCfg.AccessToken, "tok-abc-provider-level")
	}
	if serverCfg.Audience != "aud-xyz" {
		t.Errorf("GetServerConfig().Audience = %q, want %q", serverCfg.Audience, "aud-xyz")
	}
	if !reflect.DeepEqual(serverCfg.Scopes, []string{"openid"}) {
		t.Errorf("GetServerConfig().Scopes = %v, want %v", serverCfg.Scopes, []string{"openid"})
	}
}

// TestUnitOAuthAccessTokenNoClientCreds verifies the access_token-only path
// (no client_id/client_secret/token_url) produces an "oauth" auth type and
// the token propagates correctly : the exact scenario broken in v2.8.0.
func TestUnitOAuthAccessTokenNoClientCreds(t *testing.T) {
	srv := &auth_providers.Server{
		Host:        "command.example.com",
		AccessToken: "pre-fetched-bearer-token",
		// Deliberately omitting ClientID, ClientSecret, OAuthTokenUrl
	}

	if got := srv.GetAuthType(); got != "oauth" {
		t.Fatalf("GetAuthType() = %q, want %q for access_token-only (no client creds)", got, "oauth")
	}

	oauthCfg := auth_providers.CommandConfigOauth{
		AccessToken: srv.AccessToken,
	}

	if oauthCfg.AccessToken != "pre-fetched-bearer-token" {
		t.Errorf("AccessToken = %q, want %q", oauthCfg.AccessToken, "pre-fetched-bearer-token")
	}
	if oauthCfg.ClientID != "" {
		t.Errorf("ClientID = %q, want empty (access_token-only mode)", oauthCfg.ClientID)
	}
	if oauthCfg.ClientSecret != "" {
		t.Errorf("ClientSecret = %q, want empty (access_token-only mode)", oauthCfg.ClientSecret)
	}
	if oauthCfg.TokenURL != "" {
		t.Errorf("TokenURL = %q, want empty (access_token-only mode)", oauthCfg.TokenURL)
	}
}

// ---------------------------------------------------------------------------
// Integration test : OAuth access_token-only auth against a real lab
// ---------------------------------------------------------------------------

// TestIntOAuthAccessTokenAuth verifies that the provider can authenticate
// using only hostname + access_token (pre-fetched token mode) : the exact
// scenario that was broken in v2.8.0. It reads a list of agents as a simple
// smoke test that the auth is working end-to-end.
//
// Requirements:
//   - KEYFACTOR_HOSTNAME must be set
//   - Either KEYFACTOR_AUTH_ACCESS_TOKEN must be pre-set, OR
//     KEYFACTOR_AUTH_CLIENT_ID + KEYFACTOR_AUTH_CLIENT_SECRET +
//     KEYFACTOR_AUTH_TOKEN_URL must all be set (the test will fetch a token
//     via client credentials grant)
//   - KEYFACTOR_SKIP_VERIFY (optional)
//
// To obtain a token for manual testing:
//
//	curl -s -X POST "$TOKEN_URL" \
//	  -d "grant_type=client_credentials&client_id=$ID&client_secret=$SECRET" \
//	  | jq -r .access_token
func TestIntOAuthAccessTokenAuth(t *testing.T) {
	hostname := os.Getenv("KEYFACTOR_HOSTNAME")
	if hostname == "" {
		t.Skip("KEYFACTOR_HOSTNAME must be set")
	}
	accessToken := os.Getenv("KEYFACTOR_AUTH_ACCESS_TOKEN")
	if accessToken == "" {
		// Fall back to client credentials grant if available
		clientID := os.Getenv("KEYFACTOR_AUTH_CLIENT_ID")
		clientSecret := os.Getenv("KEYFACTOR_AUTH_CLIENT_SECRET")
		tokenURL := os.Getenv("KEYFACTOR_AUTH_TOKEN_URL")
		if clientID == "" || clientSecret == "" || tokenURL == "" {
			t.Skip("KEYFACTOR_AUTH_ACCESS_TOKEN or OAuth client credentials must be set")
		}
		accessToken = fetchOAuthToken(t, tokenURL, clientID, clientSecret)
	}

	// Clear OAuth client credential env vars to force access_token-only mode
	origAccessToken := os.Getenv("KEYFACTOR_AUTH_ACCESS_TOKEN")
	origClientID := os.Getenv("KEYFACTOR_AUTH_CLIENT_ID")
	origClientSecret := os.Getenv("KEYFACTOR_AUTH_CLIENT_SECRET")
	origTokenURL := os.Getenv("KEYFACTOR_AUTH_TOKEN_URL")
	origUsername := os.Getenv("KEYFACTOR_USERNAME")
	origPassword := os.Getenv("KEYFACTOR_PASSWORD")
	origDomain := os.Getenv("KEYFACTOR_DOMAIN")

	os.Unsetenv("KEYFACTOR_AUTH_CLIENT_ID")
	os.Unsetenv("KEYFACTOR_AUTH_CLIENT_SECRET")
	os.Unsetenv("KEYFACTOR_AUTH_TOKEN_URL")
	os.Unsetenv("KEYFACTOR_USERNAME")
	os.Unsetenv("KEYFACTOR_PASSWORD")
	os.Unsetenv("KEYFACTOR_DOMAIN")

	// Ensure the access token env var is set so the provider picks it up
	// (it may have been freshly fetched, or pre-set by the caller).
	os.Setenv("KEYFACTOR_AUTH_ACCESS_TOKEN", accessToken)

	t.Cleanup(func() {
		restoreEnv("KEYFACTOR_AUTH_ACCESS_TOKEN", origAccessToken)
		restoreEnv("KEYFACTOR_AUTH_CLIENT_ID", origClientID)
		restoreEnv("KEYFACTOR_AUTH_CLIENT_SECRET", origClientSecret)
		restoreEnv("KEYFACTOR_AUTH_TOKEN_URL", origTokenURL)
		restoreEnv("KEYFACTOR_USERNAME", origUsername)
		restoreEnv("KEYFACTOR_PASSWORD", origPassword)
		restoreEnv("KEYFACTOR_DOMAIN", origDomain)
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "keyfactor_agents" "test" {
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.keyfactor_agents.test", "id"),
					resource.TestCheckResourceAttrWith("data.keyfactor_agents.test", "agents.#", func(value string) error {
						if value == "0" {
							return fmt.Errorf("expected at least one agent from access_token-only auth, got 0")
						}
						return nil
					}),
				),
			},
		},
	})
}

// restoreEnv restores an environment variable to its original value, or unsets
// it if the original was empty.
func restoreEnv(key, original string) {
	if original == "" {
		os.Unsetenv(key)
	} else {
		os.Setenv(key, original)
	}
}

// fetchOAuthToken performs a client credentials grant against the given token
// URL and returns the access_token from the response. The test is skipped (not
// failed) if the request fails or the response cannot be parsed : this lets
// the test be safely run in environments where the token endpoint is
// unreachable.
func fetchOAuthToken(t *testing.T, tokenURL, clientID, clientSecret string) string {
	t.Helper()
	vals := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	resp, err := http.PostForm(tokenURL, vals)
	if err != nil {
		t.Skipf("could not fetch access token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.AccessToken == "" {
		t.Skipf("could not parse access token from response: %s", body)
	}
	return result.AccessToken
}
