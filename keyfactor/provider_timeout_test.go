package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestUnitResolveClientTimeout is a regression test for a dead-code bug in the
// provider's client-timeout precedence logic (config > env var > default).
// The original inline condition was:
//
//	if !envVarSet || (configValue > 0) { ... use configValue ... }
//
// Since `!envVarSet` alone makes the condition true, the "nothing configured"
// branch that applied auth_providers.DefaultClientTimeout was unreachable
// whenever the env var was unset -- an unset request_timeout (configValue==0)
// with no env var silently resolved to 0 instead of the documented default.
// A second, related bug logged the raw (possibly empty/invalid) env var
// string into structured logs instead of the effective timeout actually used.
//
// keyfactor-auth-client-go's ValidateAuthConfig() happens to re-apply the
// default whenever HttpClientTimeout <= 0, which is why this bug was not
// independently responsible for the customer-reported "request_timeout
// dropped" symptom (that root cause was auth_providers.Server having no field
// to carry the timeout at all -- fixed upstream). But the dead code and
// misleading log field were real defects in this function, so they are
// pinned here directly rather than relying on downstream self-healing to
// mask them again in the future.
func TestUnitResolveClientTimeout(t *testing.T) {
	cases := []struct {
		name          string
		configValue   int64
		envVarStr     string
		envVarSet     bool
		wantTimeout   int64
		wantIsWarning bool
	}{
		{
			name:        "config value wins over everything",
			configValue: 300,
			envVarStr:   "120",
			envVarSet:   true,
			wantTimeout: 300,
		},
		{
			name:        "env var used when config unset",
			configValue: 0,
			envVarStr:   "120",
			envVarSet:   true,
			wantTimeout: 120,
		},
		{
			name:        "nothing configured falls back to default (previously dead code)",
			configValue: 0,
			envVarSet:   false,
			wantTimeout: auth_providers.DefaultClientTimeout,
		},
		{
			name:          "invalid env var value falls back to default with a warning",
			configValue:   0,
			envVarStr:     "not-a-number",
			envVarSet:     true,
			wantTimeout:   auth_providers.DefaultClientTimeout,
			wantIsWarning: true,
		},
		{
			name:          "non-positive env var value falls back to default with a warning",
			configValue:   0,
			envVarStr:     "-5",
			envVarSet:     true,
			wantTimeout:   auth_providers.DefaultClientTimeout,
			wantIsWarning: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTimeout, _, gotIsWarning := resolveClientTimeout(tc.configValue, tc.envVarStr, tc.envVarSet)
			if gotTimeout != tc.wantTimeout {
				t.Errorf("resolveClientTimeout() timeout = %d, want %d", gotTimeout, tc.wantTimeout)
			}
			if gotIsWarning != tc.wantIsWarning {
				t.Errorf("resolveClientTimeout() isWarning = %v, want %v", gotIsWarning, tc.wantIsWarning)
			}
		})
	}
}

// newFakeCommandServer stands in for a Keyfactor Command instance for
// CommandAuthConfigBasic.Authenticate(), which performs a real GET against
// {host}/{apiPath}/Status/Endpoints as part of authentication. It always
// returns 200 with a valid JSON string array, regardless of credentials.
func newFakeCommandServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`["endpoint1"]`))
	}))
	t.Cleanup(server.Close)
	return server
}

// clearTimeoutEnv unsets KEYFACTOR_CLIENT_TIMEOUT for the duration of the test
// and restores it afterward, so tests exercising the config-vs-env-vs-default
// precedence aren't at the mercy of the ambient shell environment.
func clearTimeoutEnv(t *testing.T) {
	t.Helper()
	orig, had := os.LookupEnv("KEYFACTOR_CLIENT_TIMEOUT")
	os.Unsetenv("KEYFACTOR_CLIENT_TIMEOUT")
	t.Cleanup(func() {
		if had {
			os.Setenv("KEYFACTOR_CLIENT_TIMEOUT", orig)
		} else {
			os.Unsetenv("KEYFACTOR_CLIENT_TIMEOUT")
		}
	})
}

// TestUnitGetServerConfig_RequestTimeoutPropagation is a regression test for
// the customer-reported bug where the `request_timeout` provider config
// attribute was silently dropped: getServerConfig() built a CommandAuthConfig
// with WithClientTimeout(...), but the resulting *auth_providers.Server had no
// field to carry that value, so every downstream consumer (keyfactor-go-client
// v3's NewKeyfactorClient, keyfactor-go-client-sdk's buildHttpClientV2) fell
// back to the 60s default regardless of what the user configured, producing
// "net/http: timeout awaiting response headers" on long-running calls like PFX
// enrollment.
//
// This exercises getServerConfig() itself (not just a mirrored construction)
// against a fake Command server, so it also pins the fix in
// github.com/Keyfactor/keyfactor-auth-client-go (Server.ClientTimeout field).
func TestUnitGetServerConfig_RequestTimeoutPropagation(t *testing.T) {
	clearTimeoutEnv(t)
	server := newFakeCommandServer(t)
	u, uErr := url.Parse(server.URL)
	if uErr != nil {
		t.Fatalf("failed to parse test server URL: %v", uErr)
	}

	p := &provider{}
	cfg := &providerData{
		Hostname:       types.String{Value: u.Host},
		Username:       types.String{Value: "user"},
		Password:       types.String{Value: "pass"},
		Domain:         types.String{Value: "domain"},
		ApiPath:        types.String{Value: "api"},
		SkipTLSVerify:  types.Bool{Value: true},
		RequestTimeout: types.Int64{Value: 300},
	}

	srvCfg, diags := p.getServerConfig(cfg, context.Background())
	if diags.HasError() {
		t.Fatalf("getServerConfig() returned unexpected diagnostics: %v", diags)
	}

	if srvCfg.ClientTimeout != 300 {
		t.Fatalf("Server.ClientTimeout = %d, want %d", srvCfg.ClientTimeout, 300)
	}
}

// TestUnitGetServerConfig_RequestTimeoutDefault confirms that omitting
// request_timeout (and the KEYFACTOR_CLIENT_TIMEOUT env var) still resolves to
// the documented default rather than 0 -- guarding against the dead-code branch
// that previously made this path unreachable in provider.go's timeout
// resolution block.
func TestUnitGetServerConfig_RequestTimeoutDefault(t *testing.T) {
	clearTimeoutEnv(t)
	server := newFakeCommandServer(t)
	u, uErr := url.Parse(server.URL)
	if uErr != nil {
		t.Fatalf("failed to parse test server URL: %v", uErr)
	}

	p := &provider{}
	cfg := &providerData{
		Hostname:      types.String{Value: u.Host},
		Username:      types.String{Value: "user"},
		Password:      types.String{Value: "pass"},
		Domain:        types.String{Value: "domain"},
		ApiPath:       types.String{Value: "api"},
		SkipTLSVerify: types.Bool{Value: true},
		// RequestTimeout deliberately left unset (zero value).
	}

	srvCfg, diags := p.getServerConfig(cfg, context.Background())
	if diags.HasError() {
		t.Fatalf("getServerConfig() returned unexpected diagnostics: %v", diags)
	}

	if srvCfg.ClientTimeout != 60 {
		t.Fatalf("Server.ClientTimeout = %d, want default of 60", srvCfg.ClientTimeout)
	}
}

// TestUnitGetServerConfig_RequestTimeoutEnvVar confirms KEYFACTOR_CLIENT_TIMEOUT
// is honored when request_timeout is not set in the provider config block --
// the middle branch of the precedence chain (config > env > default).
func TestUnitGetServerConfig_RequestTimeoutEnvVar(t *testing.T) {
	clearTimeoutEnv(t)
	os.Setenv("KEYFACTOR_CLIENT_TIMEOUT", "120")
	defer os.Unsetenv("KEYFACTOR_CLIENT_TIMEOUT")

	server := newFakeCommandServer(t)
	u, uErr := url.Parse(server.URL)
	if uErr != nil {
		t.Fatalf("failed to parse test server URL: %v", uErr)
	}

	p := &provider{}
	cfg := &providerData{
		Hostname:      types.String{Value: u.Host},
		Username:      types.String{Value: "user"},
		Password:      types.String{Value: "pass"},
		Domain:        types.String{Value: "domain"},
		ApiPath:       types.String{Value: "api"},
		SkipTLSVerify: types.Bool{Value: true},
		// RequestTimeout deliberately left unset so the env var takes over.
	}

	srvCfg, diags := p.getServerConfig(cfg, context.Background())
	if diags.HasError() {
		t.Fatalf("getServerConfig() returned unexpected diagnostics: %v", diags)
	}

	if srvCfg.ClientTimeout != 120 {
		t.Fatalf("Server.ClientTimeout = %d, want %d from KEYFACTOR_CLIENT_TIMEOUT", srvCfg.ClientTimeout, 120)
	}
}

// TestUnitGetServerConfig_RequestTimeoutConfigOverridesEnv confirms that an
// explicit request_timeout in provider config wins over KEYFACTOR_CLIENT_TIMEOUT
// (documented precedence: config > env var > default).
func TestUnitGetServerConfig_RequestTimeoutConfigOverridesEnv(t *testing.T) {
	clearTimeoutEnv(t)
	os.Setenv("KEYFACTOR_CLIENT_TIMEOUT", "120")
	defer os.Unsetenv("KEYFACTOR_CLIENT_TIMEOUT")

	server := newFakeCommandServer(t)
	u, uErr := url.Parse(server.URL)
	if uErr != nil {
		t.Fatalf("failed to parse test server URL: %v", uErr)
	}

	p := &provider{}
	cfg := &providerData{
		Hostname:       types.String{Value: u.Host},
		Username:       types.String{Value: "user"},
		Password:       types.String{Value: "pass"},
		Domain:         types.String{Value: "domain"},
		ApiPath:        types.String{Value: "api"},
		SkipTLSVerify:  types.Bool{Value: true},
		RequestTimeout: types.Int64{Value: 300},
	}

	srvCfg, diags := p.getServerConfig(cfg, context.Background())
	if diags.HasError() {
		t.Fatalf("getServerConfig() returned unexpected diagnostics: %v", diags)
	}

	if srvCfg.ClientTimeout != 300 {
		t.Fatalf("Server.ClientTimeout = %d, want %d (config should override env)", srvCfg.ClientTimeout, 300)
	}
}

// TestUnitNewKeyfactorClient_HonorsProviderRequestTimeout is an end-to-end
// regression test proving the full plumbing: a provider-configured
// request_timeout survives getServerConfig() AND the subsequent
// keyfactor-go-client v3 NewKeyfactorClient() call, ending up as the actual
// ResponseHeaderTimeout on the transport that issues Command API requests.
func TestUnitNewKeyfactorClient_HonorsProviderRequestTimeout(t *testing.T) {
	clearTimeoutEnv(t)
	server := newFakeCommandServer(t)
	u, uErr := url.Parse(server.URL)
	if uErr != nil {
		t.Fatalf("failed to parse test server URL: %v", uErr)
	}

	p := &provider{}
	cfg := &providerData{
		Hostname:       types.String{Value: u.Host},
		Username:       types.String{Value: "user"},
		Password:       types.String{Value: "pass"},
		Domain:         types.String{Value: "domain"},
		ApiPath:        types.String{Value: "api"},
		SkipTLSVerify:  types.Bool{Value: true},
		RequestTimeout: types.Int64{Value: 300},
	}

	srvCfg, diags := p.getServerConfig(cfg, context.Background())
	if diags.HasError() {
		t.Fatalf("getServerConfig() returned unexpected diagnostics: %v", diags)
	}

	ctx := context.Background()
	client, cErr := api.NewKeyfactorClient(srvCfg, &ctx)
	if cErr != nil {
		t.Fatalf("NewKeyfactorClient() returned unexpected error: %v", cErr)
	}

	basicCfg, ok := client.AuthClient.(*auth_providers.CommandAuthConfigBasic)
	if !ok {
		t.Fatalf("expected AuthClient to be *auth_providers.CommandAuthConfigBasic, got %T", client.AuthClient)
	}

	if basicCfg.HttpClientTimeout != 300 {
		t.Fatalf("CommandAuthConfigBasic.HttpClientTimeout = %d, want %d", basicCfg.HttpClientTimeout, 300)
	}

	transport, tErr := basicCfg.CommandAuthConfig.BuildTransport()
	if tErr != nil {
		t.Fatalf("BuildTransport() returned unexpected error: %v", tErr)
	}

	expected := 300 * time.Second
	if transport.ResponseHeaderTimeout != expected {
		t.Fatalf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, expected)
	}
}
