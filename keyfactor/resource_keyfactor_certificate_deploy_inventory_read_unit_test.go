package keyfactor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
				_, _ = w.Write([]byte(`{"Message":"certificate read failed"}`))
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
