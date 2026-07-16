package keyfactor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// TestUnitLookupContainerNameByID_ListEndpointFallback is a regression test
// for GH issue #175's fix #1: an erroring by-ID lookup must not be treated as
// definitive proof the container is gone. Before this fix, a single failed
// by-ID lookup fell straight back to hint. This test simulates a by-ID
// endpoint failure (e.g. a transient/permission-scope error) alongside a
// working list endpoint that still has the container, and requires the
// resolver to find the real name via the second, independent path instead of
// silently discarding it.
func TestUnitLookupContainerNameByID_ListEndpointFallback(t *testing.T) {
	const (
		containerID   = 777
		containerName = "tf-list-fallback-app"
	)
	var byIDHits, listHits int

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/CertificateStoreContainers/%d", containerID), func(w http.ResponseWriter, r *http.Request) {
		byIDHits++
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/KeyfactorAPI/CertificateStoreContainers/", func(w http.ResponseWriter, r *http.Request) {
		listHits++
		id := containerID
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]api.CertStoreContainer{{Id: &id, Name: containerName}})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newContainerLookupClient(server)

	got := lookupContainerNameByID(context.Background(), client, containerID, "")
	if got != containerName {
		t.Fatalf("expected list-endpoint fallback to resolve %q, got %q (byIDHits=%d listHits=%d)", containerName, got, byIDHits, listHits)
	}
	if byIDHits == 0 {
		t.Fatalf("expected the by-ID endpoint to be tried first, got %d hits", byIDHits)
	}
}

// TestUnitLookupContainerNameByID_ListEndpointFallbackPagination is a
// regression test for the follow-up to GH issue #175's fix #1: the
// list-endpoint fallback calls client.GetStoreContainers(), which the SDK
// paginates server-side. Command returns only the first page's worth of
// containers per request; a container sorted beyond that first page (e.g. a
// lab/tenant with more than a page's worth of containers) would previously
// never be found via the fallback, silently falling through to hint even
// though the container is real and simply not on page 1.
//
// This test forces the by-ID lookup to fail (so the list-endpoint fallback
// runs) and serves the list endpoint as a genuinely paginated API would: a
// full first page that does NOT include the target container, followed by a
// second, shorter page that does. The fix (GetStoreContainers pagination in
// keyfactor-go-client, mirroring the GetTemplates fix for issue #172) must
// walk pages until it finds the target, rather than only inspecting page 1.
func TestUnitLookupContainerNameByID_ListEndpointFallbackPagination(t *testing.T) {
	const (
		containerID   = 4242
		containerName = "tf-late-sorted-container"
		pageSize      = 100
	)
	var byIDHits, listHits int

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/CertificateStoreContainers/%d", containerID), func(w http.ResponseWriter, r *http.Request) {
		byIDHits++
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/KeyfactorAPI/CertificateStoreContainers", func(w http.ResponseWriter, r *http.Request) {
		listHits++
		page, _ := strconv.Atoi(r.URL.Query().Get("PageReturned"))
		if page < 1 {
			page = 1
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch page {
		case 1:
			// A full first page that does NOT contain the target container —
			// simulates a lab/tenant with more containers than fit on page 1.
			fullPage := make([]api.CertStoreContainer, pageSize)
			for i := range fullPage {
				id := i + 1
				fullPage[i] = api.CertStoreContainer{Id: &id, Name: fmt.Sprintf("Container-%d", id)}
			}
			_ = json.NewEncoder(w).Encode(fullPage)
		case 2:
			id := containerID
			_ = json.NewEncoder(w).Encode([]api.CertStoreContainer{{Id: &id, Name: containerName}})
		default:
			_ = json.NewEncoder(w).Encode([]api.CertStoreContainer{})
		}
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newContainerLookupClient(server)

	got := lookupContainerNameByID(context.Background(), client, containerID, "fallback-hint")
	if got != containerName {
		t.Fatalf(
			"expected paginated list-endpoint fallback to resolve %q, got %q (byIDHits=%d listHits=%d) — "+
				"a container past page 1 of GetStoreContainers was not found",
			containerName, got, byIDHits, listHits,
		)
	}
	if byIDHits == 0 {
		t.Fatalf("expected the by-ID endpoint to be tried first, got %d hits", byIDHits)
	}
	if listHits < 2 {
		t.Fatalf("expected the list endpoint to be paged at least twice to find the target container, got %d hits", listHits)
	}
}

// TestUnitCertificateStoreUpdate_PreservesContainerAssignmentWhenNameNotDeclared
// is the red/green regression test for GH issue #175's fix #2 — the
// load-bearing fix. Root cause: Update() resolved containerId to 0 whenever
// the plan gave no explicit application_name/container_name, regardless of
// whether the store already had a real container_id in state. Because
// UpdateStoreFctArgs.ContainerId is `json:"ContainerId,omitempty"` and
// intToPointer(0) returns nil, containerId==0 is dropped from the PUT body
// entirely, and Command interprets the omitted field as "clear the
// assignment" — deleting a real, live assignment out from under the user.
//
// This test constructs a plan/state pair matching that exact scenario
// (config never declares application_name/container_name; state shows a real
// nonzero container_id — e.g. from a container assigned out-of-band) and
// calls resolveContainerAssignmentForUpdate directly. No network is
// required: the "preserve" branch this test exercises never calls the API
// client when state already has a resolved name.
func TestUnitCertificateStoreUpdate_PreservesContainerAssignmentWhenNameNotDeclared(t *testing.T) {
	r := resourceCertificateStore{p: provider{}}

	state := CertificateStore{
		ContainerID:     types.Int64{Value: 500},
		ContainerName:   types.String{Value: "existing-app", Null: false},
		ApplicationName: types.String{Value: "existing-app", Null: false},
	}
	plan := CertificateStore{
		ContainerName:   types.String{Null: true},
		ApplicationName: types.String{Null: true},
	}

	containerId, effectiveName, err := r.resolveContainerAssignmentForUpdate(context.Background(), plan, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if containerId != 500 {
		t.Fatalf(
			"expected containerId to be preserved from state (500) when plan declares no application_name/container_name, got %d — "+
				"this reproduces GH issue #175: Update() would omit ContainerId from the PUT body, and Command would clear the assignment",
			containerId,
		)
	}
	if effectiveName != "existing-app" {
		t.Fatalf("expected effectiveName to be preserved from state (%q), got %q", "existing-app", effectiveName)
	}
}

// TestUnitCertificateStoreUpdate_NoPreservationNeededWhenNeverAssigned covers
// the companion case: if the store never had a container/application
// assignment (state.ContainerID == 0) and the plan still declares none, there
// is nothing to preserve — containerId must resolve to 0 as before, and no
// warning-worthy "preserving an assignment" behavior should be inferred.
func TestUnitCertificateStoreUpdate_NoPreservationNeededWhenNeverAssigned(t *testing.T) {
	r := resourceCertificateStore{p: provider{}}

	state := CertificateStore{
		ContainerID:     types.Int64{Value: 0},
		ContainerName:   types.String{Null: true},
		ApplicationName: types.String{Null: true},
	}
	plan := CertificateStore{
		ContainerName:   types.String{Null: true},
		ApplicationName: types.String{Null: true},
	}

	containerId, _, err := r.resolveContainerAssignmentForUpdate(context.Background(), plan, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if containerId != 0 {
		t.Fatalf("expected containerId 0 when the store never had an assignment, got %d", containerId)
	}
}

// TestUnitCertificateStoreUpdate_ExplicitEmptyNameClearsAssignment is a
// regression test for a bug introduced by the fix above and caught in code
// review: effectiveContainerName() (models.go) only checks .Value != "",
// never .IsNull(), so it collapses "the attribute was never declared" and
// "the attribute was explicitly set to \"\"" into the same nameIsNull=true
// signal. The preservation logic must NOT treat an explicit
// application_name = "" (or container_name = "") as "never declared" — that
// is a deliberate user instruction to clear the assignment, and must still
// resolve containerId to 0 exactly as it did before GH issue #175's fix.
func TestUnitCertificateStoreUpdate_ExplicitEmptyNameClearsAssignment(t *testing.T) {
	r := resourceCertificateStore{p: provider{}}

	state := CertificateStore{
		ContainerID:     types.Int64{Value: 500},
		ContainerName:   types.String{Value: "existing-app", Null: false},
		ApplicationName: types.String{Value: "existing-app", Null: false},
	}
	// The user explicitly set application_name = "" in config — a known,
	// non-null (empty) value, NOT an undeclared attribute. container_name is
	// left undeclared (null); application_name still wins per
	// effectiveContainerName()'s precedence, but either field being
	// explicitly non-null must defeat the "truly undeclared" check.
	plan := CertificateStore{
		ContainerName:   types.String{Null: true},
		ApplicationName: types.String{Value: "", Null: false},
	}

	containerId, effectiveName, err := r.resolveContainerAssignmentForUpdate(context.Background(), plan, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if containerId != 0 {
		t.Fatalf(
			"expected containerId 0 when application_name is explicitly cleared to \"\", got %d — "+
				"an explicit clear was incorrectly treated as \"never declared\" and the existing assignment was preserved instead of cleared",
			containerId,
		)
	}
	if effectiveName != "" {
		t.Fatalf("expected effectiveName \"\" for an explicit clear, got %q", effectiveName)
	}
}

// TestUnitContainerNameArgPointer_NeverPairsNonzeroIdWithEmptyName is a
// regression test for a second bug caught in code review: when
// resolveContainerAssignmentForUpdate preserves a real container_id from
// state but cannot resolve its name (neither state nor a fresh API lookup
// has it — the exact GH issue #175 scenario on the very first Read() after
// an out-of-band assignment), the outgoing UpdateStoreFctArgs must never pair
// a nonzero ContainerId with a literal empty-string ContainerName — an
// untested combination whose handling by Command's UpdateStore endpoint is
// unverified. containerNameArgPointer must omit ContainerName (nil, dropped
// by `omitempty`) in that case, while still preserving the long-standing,
// tested "explicit clear" shape (containerId 0 + ContainerName "") exactly
// as before.
func TestUnitContainerNameArgPointer_NeverPairsNonzeroIdWithEmptyName(t *testing.T) {
	tests := []struct {
		name        string
		containerId int
		effName     string
		wantNil     bool
		wantValue   string
	}{
		{
			name:        "nonzero containerId with unresolved (empty) name omits ContainerName",
			containerId: 500,
			effName:     "",
			wantNil:     true,
		},
		{
			name:        "nonzero containerId with a resolved name sends it explicitly",
			containerId: 500,
			effName:     "existing-app",
			wantNil:     false,
			wantValue:   "existing-app",
		},
		{
			name:        "zero containerId (explicit clear) still sends an explicit empty ContainerName",
			containerId: 0,
			effName:     "",
			wantNil:     false,
			wantValue:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containerNameArgPointer(tt.containerId, tt.effName)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected ContainerName to be omitted (nil), got pointer to %q", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected ContainerName to be sent explicitly as %q, got nil (omitted)", tt.wantValue)
			}
			if *got != tt.wantValue {
				t.Fatalf("expected ContainerName %q, got %q", tt.wantValue, *got)
			}
		})
	}
}

// TestUnitResolveApprovedAgentID_EmptyAgentsNilErrorDoesNotPanic is the
// red/green regression test for the nil-pointer dereference in
// resolveApprovedAgentID (extracted from the Create()/Update() agent-lookup
// blocks): when GetAgent returns an empty agents slice paired with a nil
// error, the len(agents) == 0 branch called agentErr.Error() unconditionally.
// Since the preceding `agentErr != nil` branch already returns, agentErr is
// guaranteed nil in this branch, so that call panics with a nil pointer
// dereference. This exact combination is constructed directly here (bypassing
// the real GetAgent HTTP call, whose current implementation happens to always
// pair an empty result with a non-nil error) because the framework requires
// resolveApprovedAgentID to be defensive regardless of what the SDK layer
// guarantees today.
func TestUnitResolveApprovedAgentID_EmptyAgentsNilErrorDoesNotPanic(t *testing.T) {
	var agentId string
	var diags diag.Diagnostics

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("resolveApprovedAgentID panicked (nil-deref regression): %v", rec)
			}
		}()
		agentId, diags = resolveApprovedAgentID("some-agent-identifier", []api.Agent{}, nil)
	}()

	if agentId != "" {
		t.Fatalf("expected empty agentId when no agents are found, got %q", agentId)
	}
	if !diags.HasError() {
		t.Fatalf("expected a diagnostic error when no agents are found, got none")
	}
}

// TestUnitCertificateStoreUpdate_PreservedAssignmentNeverPairsWithEmptyName
// combines resolveContainerAssignmentForUpdate and containerNameArgPointer —
// the same two steps Update() performs — to directly assert the exact
// outgoing request shape code review flagged: preserving a real container_id
// whose name cannot be resolved (client is nil here, so both the by-ID and
// list-endpoint lookups inside lookupContainerNameByID no-op and return "")
// must never produce ContainerId != 0 paired with ContainerName == "".
func TestUnitCertificateStoreUpdate_PreservedAssignmentNeverPairsWithEmptyName(t *testing.T) {
	r := resourceCertificateStore{p: provider{}}

	state := CertificateStore{
		ContainerID:     types.Int64{Value: 500},
		ContainerName:   types.String{Null: true},
		ApplicationName: types.String{Null: true},
	}
	plan := CertificateStore{
		ContainerName:   types.String{Null: true},
		ApplicationName: types.String{Null: true},
	}

	containerId, effectiveName, err := r.resolveContainerAssignmentForUpdate(context.Background(), plan, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if containerId != 500 {
		t.Fatalf("expected containerId to be preserved (500), got %d", containerId)
	}
	if effectiveName != "" {
		t.Fatalf("expected effectiveName \"\" (unresolvable with a nil client), got %q", effectiveName)
	}

	namePtr := containerNameArgPointer(containerId, effectiveName)
	if containerId != 0 && namePtr != nil {
		t.Fatalf(
			"never send a nonzero ContainerId (%d) paired with a literal empty ContainerName — got pointer to %q; "+
				"ContainerName must be omitted (nil) instead",
			containerId,
			*namePtr,
		)
	}
}
