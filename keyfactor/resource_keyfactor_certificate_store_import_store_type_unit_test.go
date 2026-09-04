package keyfactor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// ---------------------------------------------------------------------------
// Regression tests for GH issue #196 (dev-harness Gap D):
//
// keyfactor_certificate_store.store_type read back as the server's DISPLAY
// name (e.g. "Kubernetes Cluster") instead of the config's SHORT name (e.g.
// "K8SCluster") immediately after `terraform import`. store_type is
// Required + RequiresReplace, so every subsequent plan compared the imported
// display name against a config declaring the short name and showed a
// spurious destroy+recreate for every imported store, even though nothing
// about the store had actually changed.
//
// Root cause: resourceCertificateStore.ImportState resolved the numeric
// store type ID via GetCertificateStoreType and used csType.Name (the
// display name) instead of csType.ShortName. The certificate_store DATA
// SOURCE (data_source_keyfactor_certificate_store.go) already resolves this
// correctly via ShortName -- the resource's ImportState simply never got the
// same treatment.
//
// This test drives resourceCertificateStore.ImportState directly against a
// local httptest server standing in for Command, and asserts the resulting
// state's store_type is the short name.
// ---------------------------------------------------------------------------

// newStoreImportTestServer returns an httptest server answering
// GET CertificateStores/{storeId} with a canned store (CertStoreType=5,
// ContainerId=0 so lookupContainerNameByID short-circuits without an extra
// HTTP call) and GET CertificateStoreTypes/5 with a store type whose Name
// (display name) and ShortName deliberately differ, the way a real K8S
// store type does on Command ("Kubernetes Cluster" / "K8SCluster").
func newStoreImportTestServer(t *testing.T, storeId string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/KeyfactorAPI/CertificateStores/"+storeId, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.GetCertificateStoreResponse{
			Id:            storeId,
			ContainerId:   0,
			ClientMachine: "k8s-cluster.example.com",
			StorePath:     "default/tls-secret",
			CertStoreType: 5,
			Approved:      true,
		})
	})
	mux.HandleFunc("/KeyfactorAPI/CertificateStoreTypes/5", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.CertificateStoreType{
			Name:      "Kubernetes Cluster",
			ShortName: "K8SCluster",
			StoreType: 5,
		})
	})
	return httptest.NewTLSServer(mux)
}

// TestUnitCertificateStoreImportStateResolvesShortName is the direct
// regression test: ImportState's resulting state.store_type must be the
// short name ("K8SCluster"), not the display name ("Kubernetes Cluster").
func TestUnitCertificateStoreImportStateResolvesShortName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const storeId = "11111111-2222-3333-4444-555555555555"
	server := newStoreImportTestServer(t, storeId)
	defer server.Close()

	client := newContainerLookupClient(server)
	r := resourceCertificateStore{p: provider{configured: true, client: client}}

	schema, diags := resourceCertificateStoreType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	req := tfsdk.ImportResourceStateRequest{ID: storeId}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	r.ImportState(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState returned diagnostics: %+v", resp.Diagnostics)
	}

	var result CertificateStore
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("failed to read back imported state: %+v", d)
	}

	if result.StoreType.Value != "K8SCluster" {
		t.Fatalf(
			"store_type after import = %q, want %q (the short name) -- this reproduces issue #196: "+
				"ImportState resolved store_type to the server's DISPLAY name instead of its SHORT name, "+
				"forcing a spurious destroy+recreate on every subsequent plan against a config that (correctly) "+
				"declares the short name",
			result.StoreType.Value, "K8SCluster",
		)
	}
}

// TestUnitCertificateStoreImportPlanStability is the plan-stability
// companion: the value ImportState produces must be stable against a config
// that declares the short name -- i.e. no diff, since that's the value
// Command actually accepts on create/update (mirroring the data source's
// existing behavior in data_source_keyfactor_certificate_store.go).
func TestUnitCertificateStoreImportPlanStability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const storeId = "11111111-2222-3333-4444-555555555555"
	server := newStoreImportTestServer(t, storeId)
	defer server.Close()

	client := newContainerLookupClient(server)
	r := resourceCertificateStore{p: provider{configured: true, client: client}}

	schema, diags := resourceCertificateStoreType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}

	req := tfsdk.ImportResourceStateRequest{ID: storeId}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	r.ImportState(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState returned diagnostics: %+v", resp.Diagnostics)
	}

	var result CertificateStore
	if d := resp.State.Get(ctx, &result); d.HasError() {
		t.Fatalf("failed to read back imported state: %+v", d)
	}

	// A config declaring the short name (the value Command's API accepts on
	// create/update, and the only representation a practitioner would ever
	// write in HCL) must exactly match the imported state -- otherwise
	// store_type's RequiresReplace plan modifier forces a destroy+recreate
	// on the very next plan.
	const configuredShortName = "K8SCluster"
	if result.StoreType.Value != configuredShortName {
		t.Errorf(
			"plan stability: imported store_type = %q, want %q to match a config declaring the short name "+
				"(a mismatch here means store_type's RequiresReplace plan modifier forces a spurious "+
				"destroy+recreate on the next plan)",
			result.StoreType.Value, configuredShortName,
		)
	}
}
