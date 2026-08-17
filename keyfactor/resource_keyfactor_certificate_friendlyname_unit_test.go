package keyfactor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	api "github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests for a "provider produced inconsistent result after apply"
// bug found and confirmed against a live Keyfactor Command lab: Update()
// hardcoded state.FriendlyName/state.UseCNAsFriendlyName into its result
// struct instead of plan.FriendlyName/plan.UseCNAsFriendlyName, even though
// friendly_name and use_cn_as_friendly_name are plain Optional (not Computed)
// schema attributes whose final value Terraform's plan step has already
// resolved from config before Update ever runs. Separately, ImportState set
// these two fields (plus collection_id) from a freshly zero-valued `state`
// struct -- a KNOWN Go zero value (empty string / false), not an explicit
// null -- which disagreed with the null Update() writes once config doesn't
// set these fields, causing a same-apply crash on the very first reconcile
// apply immediately after `terraform import`.
// ---------------------------------------------------------------------------

// buildFriendlyNameTestLeaf creates a small self-signed leaf certificate for
// driving Update()/ImportState() through their real GetCertificateContext /
// DownloadCertificate code paths without touching a live Command instance.
func buildFriendlyNameTestLeaf(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return leaf
}

// newFriendlyNameMockClient wires an api.Client to srv, mirroring the
// pattern used by the sibling Update/ImportState unit tests in this package
// (resource_keyfactor_certificate_unit_test.go,
// resource_keyfactor_certificate_import_sans_unit_test.go).
func newFriendlyNameMockClient(srv *httptest.Server) *api.Client {
	return &api.Client{
		AuthClient: &certUpdateMockAuthConfig{server: srv},
	}
}

// TestUnitKeyfactorCertificateResource_Update_FriendlyNameFollowsPlan drives
// resourceCommandCertificate.Update directly against a mock Command server
// and asserts that the resulting state's friendly_name/use_cn_as_friendly_name
// match the PLAN values, not the prior STATE values, in both the non-CSR and
// CSR branches of Update.
//
// Red/green proof: on the unfixed code, Update's result struct literals read
// `state.FriendlyName`/`state.UseCNAsFriendlyName` -- this test fails because
// the returned state still has the OLD ("state-old-friendly"/false) values
// even though the plan declared new ones. After the fix (plan.FriendlyName/
// plan.UseCNAsFriendlyName), the test passes.
func TestUnitKeyfactorCertificateResource_Update_FriendlyNameFollowsPlan(t *testing.T) {
	cases := []struct {
		name string
		csr  bool // true drives the CSR branch of Update, false the non-CSR branch
	}{
		{name: "non_csr_branch", csr: false},
		{name: "csr_branch", csr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			const certID = 845090
			const cn = "tf-unit-friendlyname-update.example.com"
			leaf := buildFriendlyNameTestLeaf(t, cn)

			certGetResp := api.GetCertificateResponse{
				Id:              certID,
				IssuedCN:        cn,
				ContentBytes:    base64.StdEncoding.EncodeToString(leaf.Raw),
				HasPrivateKey:   false,
				CertStateString: "Unknown",
			}
			getBody, err := json.Marshal(certGetResp)
			if err != nil {
				t.Fatalf("marshal certGetResp: %v", err)
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(getBody)
			})
			server := httptest.NewTLSServer(mux)
			defer server.Close()

			client := newFriendlyNameMockClient(server)

			schema, sDiags := resourceCommandCertificateType{}.GetSchema(context.Background())
			if sDiags.HasError() {
				t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
			}

			nullList := types.List{ElemType: types.StringType, Null: true}
			nullMap := types.Map{ElemType: types.StringType, Null: true}

			plan := CommandCertificate{
				ID:                   types.String{Value: "845090"},
				CertificateId:        types.Int64{Value: certID},
				CollectionId:         types.Int64{Value: 0},
				ExpiryWarningDays:    types.Int64{Null: true},
				DNSSANs:              nullList,
				IPSANs:               nullList,
				URISANs:              nullList,
				Metadata:             nullMap,
				CertificateAuthority: types.String{Null: true},
				CertificateTemplate:  types.String{Null: true},
				EnrollmentPattern:    types.String{Null: true},
				OwnerRoleName:        types.String{Null: true},
				CertificateFormat:    types.String{Null: true},
				RevokeOnDestroy:      types.Bool{Null: true},
				KeyPassword:          types.String{Null: true},
				// The values under test: the plan is what Terraform has
				// already resolved from config for this apply.
				FriendlyName:        types.String{Value: "plan-friendly"},
				UseCNAsFriendlyName: types.Bool{Value: true},
			}

			if tc.csr {
				plan.CSR = types.String{Value: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBAA==\n-----END CERTIFICATE REQUEST-----\n"}
				plan.CommonName = types.String{Null: true}
			} else {
				plan.CSR = types.String{Null: true}
				plan.CommonName = types.String{Value: cn}
			}

			// state carries the OLD friendly-name values that the plan is
			// changing away from -- exactly the scenario where the pre-fix
			// code silently ignored the plan.
			state := plan
			state.FriendlyName = types.String{Value: "state-old-friendly"}
			state.UseCNAsFriendlyName = types.Bool{Value: false}
			// State's CSR must be null regardless of branch under test so
			// that Update's `if !state.CSR.IsNull()` subject-field override
			// (irrelevant to this test) doesn't fire.
			state.CSR = types.String{Null: true}
			state.CommonName = types.String{Value: cn}

			planObj := tfsdk.Plan{Schema: schema}
			if d := planObj.Set(context.Background(), &plan); d.HasError() {
				t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
			}
			stateObj := tfsdk.State{Schema: schema}
			if d := stateObj.Set(context.Background(), &state); d.HasError() {
				t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
			}

			r := resourceCommandCertificate{p: provider{configured: true, client: client}}
			req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
			resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

			r.Update(context.Background(), req, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
			}

			var result CommandCertificate
			if d := resp.State.Get(context.Background(), &result); d.HasError() {
				t.Fatalf("failed to read back updated state: %+v", d)
			}

			if result.FriendlyName.Null || result.FriendlyName.Value != "plan-friendly" {
				t.Errorf(
					"friendly_name after Update = %+v, want the PLAN value %q -- Update must follow "+
						"Terraform's own plan for this Optional (not Computed) attribute, not silently "+
						"keep serving the prior state value (this is what caused \"provider produced "+
						"inconsistent result after apply\")",
					result.FriendlyName, "plan-friendly",
				)
			}
			if result.UseCNAsFriendlyName.Null || result.UseCNAsFriendlyName.Value != true {
				t.Errorf(
					"use_cn_as_friendly_name after Update = %+v, want the PLAN value true -- same "+
						"inconsistent-result-after-apply bug class as friendly_name",
					result.UseCNAsFriendlyName,
				)
			}
		})
	}
}

// TestUnitKeyfactorCertificateResource_ImportState_FriendlyNameFieldsNull is
// the regression test for the companion ImportState bug: collection_id,
// friendly_name, and use_cn_as_friendly_name were set from a freshly
// zero-valued `state` struct (there is no prior state to import into), which
// produced a KNOWN Go zero value (0 / "" / false) rather than an explicit
// null. That known-zero then disagreed with the null Update() writes for
// these write-only-equivalent attributes on the very next reconcile apply,
// producing "provider produced inconsistent result after apply" immediately
// after `terraform import`.
func TestUnitKeyfactorCertificateResource_ImportState_FriendlyNameFieldsNull(t *testing.T) {
	const certID = 845091
	const cn = "tf-unit-friendlyname-import.example.com"
	leaf := buildFriendlyNameTestLeaf(t, cn)

	certGetResp := api.GetCertificateResponse{
		Id:            certID,
		IssuedCN:      cn,
		ContentBytes:  base64.StdEncoding.EncodeToString(leaf.Raw),
		HasPrivateKey: false, // CSR-enrollment-style path: PEM download, no PFX recovery
	}
	getBody, err := json.Marshal(certGetResp)
	if err != nil {
		t.Fatalf("marshal certGetResp: %v", err)
	}
	downloadBody, err := json.Marshal(map[string]string{"Content": buildRootFirstP7B(t, leaf)})
	if err != nil {
		t.Fatalf("marshal download body: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch {
		case r.Method == http.MethodPost:
			_, _ = w.Write(downloadBody)
		default:
			_, _ = w.Write(getBody)
		}
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newFriendlyNameMockClient(server)

	schema, sDiags := resourceCommandCertificateType{}.GetSchema(context.Background())
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	r := resourceCommandCertificate{p: provider{configured: true, client: client}}
	req := tfsdk.ImportResourceStateRequest{ID: "845091"}
	resp := &tfsdk.ImportResourceStateResponse{State: tfsdk.State{Schema: schema}}

	r.ImportState(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("ImportState returned diagnostics: %+v", resp.Diagnostics)
	}

	var result CommandCertificate
	if d := resp.State.Get(context.Background(), &result); d.HasError() {
		t.Fatalf("failed to read back imported state: %+v", d)
	}

	if !result.CollectionId.Null {
		t.Errorf(
			"collection_id after ImportState = %+v, want explicit null -- a known zero value here "+
				"disagrees with the null Update() writes once config doesn't set collection_id, causing "+
				"\"provider produced inconsistent result after apply\" on the first reconcile apply after import",
			result.CollectionId,
		)
	}
	if !result.FriendlyName.Null {
		t.Errorf(
			"friendly_name after ImportState = %+v, want explicit null -- same inconsistent-result-after-"+
				"apply bug class as collection_id",
			result.FriendlyName,
		)
	}
	if !result.UseCNAsFriendlyName.Null {
		t.Errorf(
			"use_cn_as_friendly_name after ImportState = %+v, want explicit null -- same inconsistent-"+
				"result-after-apply bug class as collection_id",
			result.UseCNAsFriendlyName,
		)
	}
}
