package keyfactor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deployRequestLog records the requests a fake Command server saw.
type deployRequestLog struct {
	mu   sync.Mutex
	reqs []string
}

func (l *deployRequestLog) add(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, r.Method+" "+r.URL.Path)
}

// count returns how many recorded requests have the given method and a path containing substr.
func (l *deployRequestLog) count(method, substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.reqs {
		if strings.HasPrefix(s, method+" ") && strings.Contains(s, substr) {
			n++
		}
	}
	return n
}

// deployServer stands in for Command. certStatus / inventoryStatus are the HTTP status codes of
// GET Certificates/{id} and GET CertificateStores/{id}/Inventory (200 answers with a body; anything
// else is an error). Every request is logged so tests can assert which calls were (not) made.
func deployServer(t *testing.T, certStatus, inventoryStatus int, log *deployRequestLog) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/Certificates/"):
			if certStatus != http.StatusOK {
				w.WriteHeader(certStatus)
				msg := "certificate read failed"
				if certStatus == http.StatusNotFound {
					msg = "certificate not found"
				}
				_, _ = w.Write([]byte(`{"Message":"` + msg + `"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(api.GetCertificateResponse{Id: 7, Thumbprint: "AABBCC"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/Inventory"):
			if inventoryStatus != http.StatusOK {
				w.WriteHeader(inventoryStatus)
				_, _ = w.Write([]byte(`{"Message":"inventory read failed"}`))
				return
			}
			_, _ = w.Write([]byte(`[]`))
		default:
			// Any other call (the deployment job POST, store reads...) is accepted.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func deploymentPlanFor() CommandCertificateDeployment {
	return CommandCertificateDeployment{
		ID:                types.String{Unknown: true},
		CertificateId:     types.Int64{Value: 7},
		CertificateAlias:  types.String{Value: "alias"},
		StoreId:           types.String{Value: "store-1"},
		KeyPassword:       types.String{Null: true},
		JobParameters:     types.Map{Null: true, ElemType: types.StringType},
		Overwrite:         types.Bool{Null: true},
		Redeploy:          types.Bool{Null: true},
		SkipRemoval:       types.Bool{Null: true},
		IncludePrivateKey: types.Bool{Null: true},
	}
}

func runDeploymentCreate(t *testing.T, srv *httptest.Server) *tfsdk.CreateResourceResponse {
	t.Helper()
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, deploymentPlanFor()).Raw}
	res := resourceCommandCertificateDeployment{p: provider{configured: true, client: newTemplateTestClient(srv)}}
	resp := &tfsdk.CreateResourceResponse{State: emptyState(ctx, schema)}
	require.NotPanics(t, func() { res.Create(ctx, tfsdk.CreateResourceRequest{Plan: plan}, resp) })
	return resp
}

func runDeploymentUpdate(t *testing.T, srv *httptest.Server) *tfsdk.UpdateResourceResponse {
	t.Helper()
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	st := stateWith(t, schema, deploymentPlanFor())
	plan := tfsdk.Plan{Schema: schema, Raw: st.Raw}
	res := resourceCommandCertificateDeployment{p: provider{configured: true, client: newTemplateTestClient(srv)}}
	resp := &tfsdk.UpdateResourceResponse{State: st}
	require.NotPanics(t, func() { res.Update(ctx, tfsdk.UpdateResourceRequest{Plan: plan, State: st}, resp) })
	return resp
}

// F1: an inventory READ error during the initial "is it already deployed?" check is not "not
// deployed". Create must surface the error and must not submit a deployment job.
func TestUnitDeploymentCreate_InventoryReadErrorDoesNotSubmitDeployment(t *testing.T) {
	var log deployRequestLog
	srv := deployServer(t, http.StatusOK, http.StatusInternalServerError, &log)

	resp := runDeploymentCreate(t, srv)

	require.True(t, resp.Diagnostics.HasError(), "an unreadable inventory must be an error: %v", resp.Diagnostics)
	assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "no deployment job was submitted")
	assert.Zero(t, log.count(http.MethodPost, ""), "no deployment job (POST) may be submitted when the inventory could not be read")
	assert.Zero(t, log.count(http.MethodPut, ""), "no write of any kind may be issued")
}

func TestUnitDeploymentUpdate_InventoryReadErrorDoesNotSubmitDeployment(t *testing.T) {
	var log deployRequestLog
	srv := deployServer(t, http.StatusOK, http.StatusInternalServerError, &log)

	resp := runDeploymentUpdate(t, srv)

	require.True(t, resp.Diagnostics.HasError(), "an unreadable inventory must be an error: %v", resp.Diagnostics)
	assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "no deployment job was submitted")
	assert.Zero(t, log.count(http.MethodPost, ""), "no deployment job (POST) may be submitted when the inventory could not be read")
}

// F4: when the certificate itself cannot be read there is nothing to deploy or to look for in the
// inventory: return right after the read error instead of carrying on with a nil certificate.
func TestUnitDeploymentCreate_CertificateReadErrorStopsImmediately(t *testing.T) {
	var log deployRequestLog
	srv := deployServer(t, http.StatusInternalServerError, http.StatusOK, &log)

	resp := runDeploymentCreate(t, srv)

	require.True(t, resp.Diagnostics.HasError())
	assert.Len(t, resp.Diagnostics.Errors(), 1, "only the certificate read error is expected: %v", resp.Diagnostics)
	assert.Zero(t, log.count(http.MethodGet, "/Inventory"), "the inventory must not be consulted without a certificate")
	assert.Zero(t, log.count(http.MethodPost, ""), "no deployment job may be submitted without a certificate")
}

func TestUnitDeploymentUpdate_CertificateReadErrorStopsImmediately(t *testing.T) {
	var log deployRequestLog
	srv := deployServer(t, http.StatusInternalServerError, http.StatusOK, &log)

	resp := runDeploymentUpdate(t, srv)

	require.True(t, resp.Diagnostics.HasError())
	assert.Len(t, resp.Diagnostics.Errors(), 1, "only the certificate read error is expected: %v", resp.Diagnostics)
	assert.Zero(t, log.count(http.MethodGet, "/Inventory"), "the inventory must not be consulted without a certificate")
	assert.Zero(t, log.count(http.MethodPost, ""), "no deployment job may be submitted without a certificate")
}

// ---- Class A: Read must not dereference the result of a failed certificate read. ----

func runDeploymentRead(t *testing.T, srv *httptest.Server) (*tfsdk.ReadResourceResponse, tfsdk.State) {
	t.Helper()
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	st := stateWith(t, schema, deploymentPlanFor())
	res := resourceCommandCertificateDeployment{p: provider{configured: true, client: newTemplateTestClient(srv)}}
	resp := &tfsdk.ReadResourceResponse{State: st}
	require.NotPanics(t, func() { res.Read(ctx, tfsdk.ReadResourceRequest{State: st}, resp) },
		"a failed certificate read must not be dereferenced")
	return resp, st
}

// The certificate no longer exists in Command: the deployment cannot be tracked, so Read removes it
// from state with a warning (the next plan shows it as missing) instead of panicking.
func TestUnitDeploymentRead_CertificateGoneRemovesFromState(t *testing.T) {
	var log deployRequestLog
	srv := deployServer(t, http.StatusNotFound, http.StatusOK, &log)

	resp, _ := runDeploymentRead(t, srv)

	assert.False(t, resp.Diagnostics.HasError(), "a gone certificate is drift, not an error: %v", resp.Diagnostics)
	assert.True(t, resp.State.Raw.IsNull(), "the deployment must be removed from state")
	assert.Equal(t, 1, countDiagsBySeverity(resp.Diagnostics, diag.SeverityWarning), "%v", resp.Diagnostics)
}

// Any other failure says nothing about whether the deployment exists: report it and keep the state.
func TestUnitDeploymentRead_OtherCertificateReadErrorIsAnErrorAndKeepsState(t *testing.T) {
	var log deployRequestLog
	srv := deployServer(t, http.StatusInternalServerError, http.StatusOK, &log)

	resp, before := runDeploymentRead(t, srv)

	require.True(t, resp.Diagnostics.HasError())
	assert.Len(t, resp.Diagnostics.Errors(), 1, "%v", resp.Diagnostics)
	assert.False(t, resp.State.Raw.IsNull(), "state must be left alone on a transient failure")
	assert.True(t, before.Raw.Equal(resp.State.Raw), "state must be unchanged")
}

// ---- #4: include_private_key = false must not overwrite an entry held by a different certificate. ----

// inventoryServer is deployServer with a configurable inventory (served on page 1 only).
func inventoryServer(t *testing.T, inv []api.CertStoreInventory, log *deployRequestLog) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/Certificates/"):
			_ = json.NewEncoder(w).Encode(api.GetCertificateResponse{Id: 7, Thumbprint: "AABBCC"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/Inventory"):
			if r.URL.Query().Get("query.pageReturned") == "1" {
				_ = json.NewEncoder(w).Encode(inv)
				return
			}
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost:
			// The deployment job submission answers with a list of job IDs.
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runDeploymentCreateWith(t *testing.T, srv *httptest.Server, plan CommandCertificateDeployment) *tfsdk.CreateResourceResponse {
	t.Helper()
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	pl := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, plan).Raw}
	res := resourceCommandCertificateDeployment{p: provider{configured: true, client: newTemplateTestClient(srv)}}
	resp := &tfsdk.CreateResourceResponse{State: emptyState(ctx, schema)}
	require.NotPanics(t, func() { res.Create(ctx, tfsdk.CreateResourceRequest{Plan: pl}, resp) })
	return resp
}

func TestUnitDeploymentCreate_NoPrivateKeyRefusesAliasOccupiedByAnotherCertificate(t *testing.T) {
	var log deployRequestLog
	srv := inventoryServer(t, []api.CertStoreInventory{
		{Name: "alias", Certificates: []api.InventoriedCertificate{{Id: 99}}},
	}, &log)
	plan := deploymentPlanFor()
	plan.IncludePrivateKey = types.Bool{Value: false}

	resp := runDeploymentCreateWith(t, srv, plan)

	require.True(t, resp.Diagnostics.HasError(), "an occupied alias must be refused: %v", resp.Diagnostics)
	assert.Contains(t, resp.Diagnostics.Errors()[0].Summary(), "occupied")
	assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "alias")
	assert.Zero(t, log.count(http.MethodPost, ""), "no deployment job may overwrite the other certificate's entry")
}

func TestUnitDeploymentCreate_NoPrivateKeyAllowsFreeAliasAndOtherAliases(t *testing.T) {
	var log deployRequestLog
	srv := inventoryServer(t, []api.CertStoreInventory{
		{Name: "someone-else", Certificates: []api.InventoriedCertificate{{Id: 99}}},
	}, &log)
	plan := deploymentPlanFor()
	plan.IncludePrivateKey = types.Bool{Value: false}

	resp := runDeploymentCreateWith(t, srv, plan)

	assert.False(t, resp.Diagnostics.HasError(), "a free alias must still deploy: %v", resp.Diagnostics)
	assert.Equal(t, 1, log.count(http.MethodPost, ""), "exactly one deployment job")
}

// The guard applies only to include_private_key = false: with the default (true) an occupied alias is
// governed by `overwrite` exactly as before.
func TestUnitDeploymentCreate_WithPrivateKeyOccupiedAliasIsNotBlocked(t *testing.T) {
	var log deployRequestLog
	srv := inventoryServer(t, []api.CertStoreInventory{
		{Name: "alias", Certificates: []api.InventoriedCertificate{{Id: 99}}},
	}, &log)

	resp := runDeploymentCreateWith(t, srv, deploymentPlanFor())

	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Equal(t, 1, log.count(http.MethodPost, ""))
}

// An alias-less deployment has no entry name to compare, so another certificate's entry (which has a
// name) is not "the target" and does not block; the certificate's own entry still does.
func TestUnitDeploymentCreate_NoPrivateKeyAliasLessStore(t *testing.T) {
	aliasLess := func() CommandCertificateDeployment {
		p := deploymentPlanFor()
		p.CertificateAlias = types.String{Null: true}
		p.IncludePrivateKey = types.Bool{Value: false}
		return p
	}

	var log deployRequestLog
	other := inventoryServer(t, []api.CertStoreInventory{
		{Name: "secret-a", Certificates: []api.InventoriedCertificate{{Id: 99}}},
	}, &log)
	resp := runDeploymentCreateWith(t, other, aliasLess())
	assert.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Equal(t, 1, log.count(http.MethodPost, ""))

	var log2 deployRequestLog
	own := inventoryServer(t, []api.CertStoreInventory{
		{Name: "secret-a", Certificates: []api.InventoriedCertificate{{Id: 7}}},
	}, &log2)
	resp = runDeploymentCreateWith(t, own, aliasLess())
	require.True(t, resp.Diagnostics.HasError(), "the certificate's own entry still blocks")
	assert.Zero(t, log2.count(http.MethodPost, ""))
}

// ---- Class B: job_parameters conversion diagnostics are returned, not dropped. ----

func TestUnitJobParametersFromPlan(t *testing.T) {
	ctx := context.Background()

	got, diags := jobParametersFromPlan(ctx, types.Map{Null: true, ElemType: types.StringType})
	assert.Nil(t, got)
	assert.False(t, diags.HasError())

	got, diags = jobParametersFromPlan(ctx, types.Map{ElemType: types.StringType, Elems: map[string]attr.Value{"k": types.String{Value: "v"}}})
	assert.False(t, diags.HasError())
	assert.Equal(t, map[string]string{"k": "v"}, got)

	_, diags = jobParametersFromPlan(ctx, types.Map{ElemType: types.Int64Type, Elems: map[string]attr.Value{"k": types.Int64{Value: 1}}})
	assert.True(t, diags.HasError(), "a map that cannot be converted to strings must produce an error diagnostic")
}

// ---- Class A: forceIfTrue stops at the first conversion error. ----

// failingBool is a Bool whose Terraform-value conversion fails.
type failingBool struct{ types.Bool }

func (failingBool) ToTerraformValue(context.Context) (tftypes.Value, error) {
	return tftypes.Value{}, errors.New("conversion failed")
}

func TestUnitForceIfTrue_ConversionErrorIsReportedOnceAndNotUsed(t *testing.T) {
	var force bool
	var diags diag.Diagnostics
	require.NotPanics(t, func() {
		force, diags = forceIfTrue(context.Background(), types.Bool{Null: true}, failingBool{}, path.Root("redeploy"))
	})
	assert.False(t, force)
	assert.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityError), "one error, not one per step: %v", diags)

	force, diags = forceIfTrue(context.Background(), types.Bool{Null: true}, types.Bool{Value: true}, path.Root("redeploy"))
	assert.True(t, force)
	assert.False(t, diags.HasError())
}
