package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
)

// containerLookupMockAuthConfig implements api.AuthConfig for httptest-backed
// unit tests of the container-name resolver.
type containerLookupMockAuthConfig struct {
	server *httptest.Server
}

func (m *containerLookupMockAuthConfig) GetServerConfig() *auth_providers.Server {
	// url.Parse needs a scheme; the client overrides http→https in sendRequest
	// but still requires the URL to parse cleanly. httptest.NewTLSServer.URL
	// already starts with "https://".
	return &auth_providers.Server{
		Host:          m.server.URL,
		APIPath:       "KeyfactorAPI",
		SkipTLSVerify: true,
	}
}

func (m *containerLookupMockAuthConfig) GetHttpClient() (*http.Client, error) {
	return m.server.Client(), nil
}

func (m *containerLookupMockAuthConfig) Authenticate() error       { return nil }
func (m *containerLookupMockAuthConfig) GetCommandVersion() string { return "25.1.0.0" }

func newContainerLookupClient(server *httptest.Server) *api.Client {
	return &api.Client{
		AuthClient: &containerLookupMockAuthConfig{server: server},
	}
}

// TestUnitLookupContainerNameByID_ByIDEndpointWins is a regression test for
// ADO #86114 ("Provider produced inconsistent result after apply" when
// application_name is interpolated from another resource in the same apply).
//
// Root cause: the previous resolver fetched the full container list via
// GetStoreContainers(), which is paginated server-side (default 50/page). A
// container created earlier in the same apply may not appear on the first
// page, causing the resolver to return "" and silently null out
// application_name/container_name in state — disagreeing with the plan.
//
// This test runs against an httptest server that returns an EMPTY list from
// the paginated endpoint while serving the just-created container only via
// the by-ID endpoint, simulating the production failure mode. The fixed
// resolver MUST query by ID and return the correct name.
func TestUnitLookupContainerNameByID_ByIDEndpointWins(t *testing.T) {
	const (
		containerID   = 1283
		containerName = "tf-int-cnt-1778611619436137000"
	)
	var listHits, byIDHits int

	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/CertificateStoreContainers", func(w http.ResponseWriter, r *http.Request) {
		// Simulate the paginated list endpoint NOT returning the new container.
		listHits++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]api.CertStoreContainer{})
	})
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/CertificateStoreContainers/%d", containerID), func(w http.ResponseWriter, r *http.Request) {
		byIDHits++
		id := containerID
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(api.CertStoreContainer{Id: &id, Name: containerName})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newContainerLookupClient(server)

	got := lookupContainerNameByID(context.Background(), client, containerID, "fallback-hint")
	if got != containerName {
		t.Fatalf("expected %q, got %q (listHits=%d byIDHits=%d)", containerName, got, listHits, byIDHits)
	}
	if byIDHits == 0 {
		t.Fatalf("expected at least one call to the by-ID endpoint, got %d (listHits=%d)", byIDHits, listHits)
	}
}

// TestUnitLookupContainerNameByID_FallsBackToHint covers the case where the
// by-ID endpoint fails (e.g. transient 5xx). The resolver must return the
// supplied hint rather than nulling the field, so Plan→Apply round-tripping
// still satisfies the framework's consistency check.
func TestUnitLookupContainerNameByID_FallsBackToHint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/CertificateStoreContainers/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newContainerLookupClient(server)

	got := lookupContainerNameByID(context.Background(), client, 42, "plan-hint")
	if got != "plan-hint" {
		t.Fatalf("expected fallback to hint %q, got %q", "plan-hint", got)
	}
}

// TestUnitLookupContainerNameByID_ZeroIDReturnsEmpty verifies the no-container
// path: when ContainerId is 0, we must return "" so the caller can null the
// field, even if the API client is non-nil.
func TestUnitLookupContainerNameByID_ZeroIDReturnsEmpty(t *testing.T) {
	got := lookupContainerNameByID(context.Background(), nil, 0, "anything")
	if got != "" {
		t.Fatalf("expected empty result for container ID 0, got %q", got)
	}
}
