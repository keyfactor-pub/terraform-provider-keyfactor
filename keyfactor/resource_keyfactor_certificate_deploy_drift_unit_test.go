package keyfactor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDeployCommand stands in for Command for the deployment drift (Read)
// tests. Unlike deployServer/inventoryServer it also serves the certificate's Locations and the
// store's inventory schedule.
type fakeDeployCommand struct {
	certStatus  int // GET Certificates/{id}; 0 means 200
	locations   []api.CertificateLocations
	storeStatus int  // GET CertificateStores/{id}; 0 means 200
	schedule    bool // the store has an inventory schedule
	invStatus   int  // GET CertificateStores/{id}/Inventory; 0 means 200
	inventory   []api.CertStoreInventory

	log deployRequestLog
}

func (f *fakeDeployCommand) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.log.add(r)
		w.Header().Set("Content-Type", "application/json")
		fail := func(status int, msg string) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"Message":"` + msg + `"}`))
		}
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/Inventory"):
			if f.invStatus != 0 && f.invStatus != http.StatusOK {
				fail(f.invStatus, "inventory read failed")
				return
			}
			if r.URL.Query().Get("query.pageReturned") == "1" {
				_ = json.NewEncoder(w).Encode(f.inventory)
				return
			}
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/Certificates/"):
			if f.certStatus != 0 && f.certStatus != http.StatusOK {
				msg := "certificate read failed"
				if f.certStatus == http.StatusNotFound {
					msg = "certificate not found"
				}
				fail(f.certStatus, msg)
				return
			}
			_ = json.NewEncoder(w).Encode(api.GetCertificateResponse{Id: 7, Thumbprint: "AABBCC", Locations: f.locations})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/CertificateStores/"):
			if f.storeStatus != 0 && f.storeStatus != http.StatusOK {
				msg := "store read failed"
				if f.storeStatus == http.StatusNotFound {
					msg = "Certificate store with id of 'store-1' does not exist"
				}
				fail(f.storeStatus, msg)
				return
			}
			resp := api.GetCertificateStoreResponse{Id: "store-1"}
			if f.schedule {
				resp.InventorySchedule = api.InventorySchedule{Interval: &api.InventoryInterval{Minutes: 60}}
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeDeployCommand) read(t *testing.T) (*tfsdk.ReadResourceResponse, tfsdk.State) {
	t.Helper()
	return runDeploymentRead(t, f.server(t))
}

// ---- Read: a certificate removed from the store out of band is drift ----

// deploymentPlanFor() deploys certificate 7 to store "store-1" under alias "alias".
func locationOf(storeId, alias string, chainLevel int) api.CertificateLocations {
	return api.CertificateLocations{CertStoreId: storeId, Alias: alias, ChainLevel: chainLevel}
}

func warningSummaries(diags diag.Diagnostics) []string {
	var out []string
	for _, d := range diags.Warnings() {
		out = append(out, d.Summary())
	}
	return out
}

// The certificate exists in Command but neither its Locations nor the (scheduled) store's inventory
// list it in the store: it was removed out of band. Read drops the deployment from state with a warning
// so the plan shows a create and apply redeploys.
func TestUnitDeploymentRead_MissingFromStoreIsRemovedFromState(t *testing.T) {
	f := &fakeDeployCommand{
		schedule:  true,
		locations: []api.CertificateLocations{locationOf("other-store", "alias", 0)},
		inventory: []api.CertStoreInventory{{Name: "someone-else", Certificates: []api.InventoriedCertificate{{Id: 99}}}},
	}

	resp, _ := f.read(t)

	assert.False(t, resp.Diagnostics.HasError(), "drift is not an error: %v", resp.Diagnostics)
	assert.True(t, resp.State.Raw.IsNull(), "a deployment that is no longer in the store must be removed from state")
	require.Len(t, resp.Diagnostics.Warnings(), 1, "%v", resp.Diagnostics)
	detail := resp.Diagnostics.Warnings()[0].Detail()
	assert.Contains(t, detail, "no longer in store 'store-1'")
	assert.Contains(t, detail, "alias 'alias'")
	assert.Contains(t, detail, "redeployed on the next apply")
}

// The certificate's Locations list the store and alias: still deployed, state kept, and no extra
// calls (the Locations are already part of the certificate read).
func TestUnitDeploymentRead_PresentInLocationsKeepsState(t *testing.T) {
	f := &fakeDeployCommand{
		schedule:  true,
		locations: []api.CertificateLocations{locationOf("store-1", "alias", 0)},
	}

	resp, before := f.read(t)

	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, resp.Diagnostics.Warnings(), "%v", resp.Diagnostics)
	assert.True(t, before.Raw.Equal(resp.State.Raw), "state must be kept")
	assert.Zero(t, f.log.count(http.MethodGet, "/Inventory"), "a present deployment needs no inventory read")
	assert.Zero(t, f.log.count(http.MethodGet, "/CertificateStores/"), "a present deployment needs no store read")
}

// The store GUID in the Locations is not guaranteed to have the same case as the one in the config.
func TestUnitDeploymentRead_LocationStoreIdIsCaseInsensitive(t *testing.T) {
	f := &fakeDeployCommand{
		schedule:  true,
		locations: []api.CertificateLocations{locationOf("STORE-1", "alias", 0)},
	}

	resp, before := f.read(t)

	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.True(t, before.Raw.Equal(resp.State.Raw))
	assert.Zero(t, f.log.count(http.MethodGet, "/Inventory"))
}

// Lag: Command has not refreshed the certificate's Locations yet, but the store inventory (what Create
// validated against before it returned) lists the deployment. The just-created deployment must not flap.
func TestUnitDeploymentRead_LocationsLagButInventoryHasItKeepsState(t *testing.T) {
	f := &fakeDeployCommand{
		schedule:  true,
		locations: nil,
		inventory: []api.CertStoreInventory{{Name: "alias", Certificates: []api.InventoriedCertificate{{Id: 7}}}},
	}

	resp, before := f.read(t)

	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, resp.Diagnostics.Warnings(), "%v", resp.Diagnostics)
	assert.True(t, before.Raw.Equal(resp.State.Raw), "the deployment is in the inventory, so it still exists")
}

// A store without an inventory schedule is never refreshed on its own, and Create does not validate
// against it either, so an empty Locations/inventory cannot be told from "not inventoried yet". No drift
// is reported (otherwise every apply would redeploy), and the inventory is not even consulted.
func TestUnitDeploymentRead_StoreWithoutInventoryScheduleReportsNoDrift(t *testing.T) {
	f := &fakeDeployCommand{schedule: false}

	resp, before := f.read(t)

	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, resp.Diagnostics.Warnings(), "%v", resp.Diagnostics)
	assert.True(t, before.Raw.Equal(resp.State.Raw), "state must be kept for an unscheduled store")
	assert.Zero(t, f.log.count(http.MethodGet, "/Inventory"))
}

// A failed inventory or store read says nothing about whether the deployment exists: error, keep state.
func TestUnitDeploymentRead_InventoryReadErrorIsAnErrorAndKeepsState(t *testing.T) {
	f := &fakeDeployCommand{schedule: true, invStatus: http.StatusInternalServerError}

	resp, before := f.read(t)

	require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Len(t, resp.Diagnostics.Errors(), 1, "%v", resp.Diagnostics)
	assert.False(t, resp.State.Raw.IsNull(), "state must be left alone on a transient failure")
	assert.True(t, before.Raw.Equal(resp.State.Raw))
}

func TestUnitDeploymentRead_StoreReadErrorIsAnErrorAndKeepsState(t *testing.T) {
	f := &fakeDeployCommand{storeStatus: http.StatusInternalServerError}

	resp, before := f.read(t)

	require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Len(t, resp.Diagnostics.Errors(), 1, "%v", resp.Diagnostics)
	assert.False(t, resp.State.Raw.IsNull())
	assert.True(t, before.Raw.Equal(resp.State.Raw))
}

// The certificate itself is gone from Command: unchanged behaviour (warning, removed from state), with
// no store/inventory calls.
func TestUnitDeploymentRead_CertificateGoneStillRemovesFromStateWithoutStoreCalls(t *testing.T) {
	f := &fakeDeployCommand{certStatus: http.StatusNotFound, schedule: true}

	resp, _ := f.read(t)

	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.True(t, resp.State.Raw.IsNull())
	assert.Equal(t, []string{"Certificate deployment not found."}, warningSummaries(resp.Diagnostics))
	assert.Zero(t, f.log.count(http.MethodGet, "/Inventory"))
}

// Alias-less deployments are matched by certificate ID, the leaf of an entry (chain level 0).
func TestUnitDeploymentRead_AliasLessMatchesByCertificateId(t *testing.T) {
	aliasLess := func() CommandCertificateDeployment {
		p := deploymentPlanFor()
		p.CertificateAlias = types.String{Null: true}
		return p
	}
	run := func(f *fakeDeployCommand) (*tfsdk.ReadResourceResponse, tfsdk.State) {
		ctx := context.Background()
		schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
		require.False(t, d.HasError())
		st := stateWith(t, schema, aliasLess())
		res := resourceCommandCertificateDeployment{p: provider{configured: true, client: newTemplateTestClient(f.server(t))}}
		resp := &tfsdk.ReadResourceResponse{State: st}
		res.Read(ctx, tfsdk.ReadResourceRequest{State: st}, resp)
		return resp, st
	}

	// Listed as the leaf of some entry of the store: present (whatever the entry is called).
	f := &fakeDeployCommand{schedule: true, locations: []api.CertificateLocations{locationOf("store-1", "secret-a", 0)}}
	resp, before := run(f)
	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.True(t, before.Raw.Equal(resp.State.Raw))

	// Only listed in another store: gone.
	f = &fakeDeployCommand{
		schedule:  true,
		locations: []api.CertificateLocations{locationOf("other-store", "secret-a", 0)},
		inventory: []api.CertStoreInventory{{Name: "secret-a", Certificates: []api.InventoriedCertificate{{Id: 99}}}},
	}
	resp, _ = run(f)
	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.True(t, resp.State.Raw.IsNull())
}

// The resource description documents the drift behaviour and its inventory-schedule precondition.
func TestUnitDeploymentDescription_DocumentsDriftAndInventoryScheduleCondition(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())

	for name, desc := range map[string]string{"Description": schema.Description, "MarkdownDescription": schema.MarkdownDescription} {
		assert.Contains(t, desc, "removed from the store outside Terraform", name)
		assert.Contains(t, desc, "inventory schedule", name)
	}
}

// ---- Read: store deleted out of band, alias-less rendering ----

// Bug class: a store/object "not found" surfaced as a generic read error. The certificate still exists
// in Command but its store was deleted out of band: Read must fail (the deployment's fate is unknown and
// it cannot be redeployed), keep the prior state, and say explicitly that the store cannot be found,
// naming the store and the deployment and how to recover.
func TestUnitDeploymentRead_StoreDeletedOutOfBandIsAnExplicitStoreNotFoundError(t *testing.T) {
	f := &fakeDeployCommand{
		storeStatus: http.StatusNotFound,
		locations:   []api.CertificateLocations{locationOf("other-store", "alias", 0)},
	}

	resp, before := f.read(t)

	require.True(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, resp.Diagnostics.Errors(), 1, "%v", resp.Diagnostics)
	e := resp.Diagnostics.Errors()[0]
	assert.Equal(t, "Certificate store not found.", e.Summary())
	assert.Contains(t, e.Detail(), "'store-1'")
	assert.Contains(t, e.Detail(), "certificate '7'")
	assert.Contains(t, e.Detail(), "alias 'alias'")
	assert.Contains(t, e.Detail(), "terraform state rm")
	assert.Contains(t, e.Detail(), "-refresh=false")
	assert.False(t, resp.State.Raw.IsNull(), "the prior state must be kept")
	assert.True(t, before.Raw.Equal(resp.State.Raw))
	assert.Empty(t, resp.Diagnostics.Warnings(), "%v", resp.Diagnostics)
}

// A store read failing for any other reason keeps the generic read error (not the store-not-found one).
func TestUnitDeploymentRead_OtherStoreReadErrorKeepsGenericSummary(t *testing.T) {
	f := &fakeDeployCommand{storeStatus: http.StatusInternalServerError}

	resp, _ := f.read(t)

	require.Len(t, resp.Diagnostics.Errors(), 1, "%v", resp.Diagnostics)
	assert.Equal(t, "Deployment read error.", resp.Diagnostics.Errors()[0].Summary())
}

func TestUnitIsStoreNotFoundError(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"nil":                           {nil, false},
		"JSON 404 body, does not exist": {errors.New("Certificate store with id of 'x' does not exist"), true},
		"JSON 404 body, not found":      {errors.New("Certificate Store not found."), true},
		"non-JSON 404 fallback":         {errors.New("404 - Unknown error connecting to Keyfactor CertificateStores/x, please check your connection."), true},
		"5xx fallback with 404 in path": {errors.New("500 - Unknown error connecting to Keyfactor CertificateStores/1404, please check your connection."), false},
		"500 message":                   {errors.New("An error occurred."), false},
		"auth failure":                  {errors.New("401 - Unauthorized: Access is denied due to invalid credentials"), false},
		"network":                       {errors.New("dial tcp: connection refused"), false},
	} {
		t.Run(name, func(t *testing.T) { assert.Equal(t, tc.want, isStoreNotFoundError(tc.err)) })
	}
}

// Bug class: an empty alias rendered as "(alias ”)" / "'store ()'" in deployment diagnostics.
func TestUnitDeploymentDiagnostics_AliasLessAreRenderedWithoutEmptyAlias(t *testing.T) {
	assert.Equal(t, "'s1 (a1)'", deploymentTargetLabel("s1", "a1"))
	assert.Equal(t, "'s1'", deploymentTargetLabel("s1", ""))
	assert.Equal(t, " (a1)", aliasParenthetical("a1"))
	assert.Equal(t, "", aliasParenthetical(""))

	with := removedFromStoreWarningDetail(7, "s1", "a1")
	assert.Equal(t, "Certificate '7' is no longer in store 's1' (alias 'a1'); it will be redeployed on the next apply.", with)
	without := removedFromStoreWarningDetail(7, "s1", "")
	assert.Equal(t, "Certificate '7' is no longer in store 's1'; it will be redeployed on the next apply.", without)
	for _, d := range []string{with, without} {
		assert.Contains(t, d, "no longer in store")
		assert.Contains(t, d, "redeployed")
	}

	_, detail := storeNotFoundDiagnostic(7, "s1", "")
	assert.NotContains(t, detail, "alias")
}

// An alias-less deployment removed from its store yields the warning without an empty alias clause.
func TestUnitDeploymentRead_AliasLessRemovalWarningHasNoEmptyAlias(t *testing.T) {
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	p := deploymentPlanFor()
	p.CertificateAlias = types.String{Null: true}
	st := stateWith(t, schema, p)
	f := &fakeDeployCommand{
		schedule:  true,
		locations: []api.CertificateLocations{locationOf("other-store", "secret-a", 0)},
		inventory: []api.CertStoreInventory{{Name: "secret-a", Certificates: []api.InventoriedCertificate{{Id: 99}}}},
	}
	res := resourceCommandCertificateDeployment{p: provider{configured: true, client: newTemplateTestClient(f.server(t))}}
	resp := &tfsdk.ReadResourceResponse{State: st}
	res.Read(ctx, tfsdk.ReadResourceRequest{State: st}, resp)

	require.Len(t, resp.Diagnostics.Warnings(), 1, "%v", resp.Diagnostics)
	detail := resp.Diagnostics.Warnings()[0].Detail()
	assert.NotContains(t, detail, "alias")
	assert.Contains(t, detail, "no longer in store 'store-1'")
	assert.Contains(t, detail, "redeployed")
}

// The resource description documents the inventory-lag limitation of drift detection.
func TestUnitDeploymentDescription_DocumentsInventoryLagLimitation(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	for name, desc := range map[string]string{"Description": schema.Description, "MarkdownDescription": schema.MarkdownDescription} {
		assert.Contains(t, desc, "as current as the last inventory job", name)
		assert.Contains(t, desc, "reported as removed and redeployed", name)
	}
}
