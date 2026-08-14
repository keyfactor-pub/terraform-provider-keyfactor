package keyfactor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// newCertUpdateMockClient builds an api.Client backed by an httptest server,
// for unit tests of the certificate resource Update path. See mockAuthConfig
// in test_helpers_test.go.
func newCertUpdateMockClient(server *httptest.Server) *api.Client {
	return &api.Client{
		AuthClient: newCertAPIMockAuthConfig(server),
	}
}

// TestUnitKeyfactorCertificateResource_UpdateNilGetResponse is a regression test
// for the SIGSEGV nil-pointer dereference in resourceCommandCertificate.Update
// that crashed `terraform apply` during an in-place update.
//
// Root cause: GetCertificateContext returns (nil, err) on failure, but the code
// only logged a warning via hasAPIErrors and then dereferenced
// certGetResp.ContentBytes (via parseLeafCert), panicking. The Read path was
// hardened with `certGetResp != nil` guards in v2.9.0; the fix aligns Update by
// returning at the hasAPIErrors branch.
//
// What this test exercises: the GET fails (HTTP 500), so GetCertificateContext
// returns (nil, err) and hasAPIErrors early-returns a clean diagnostic instead
// of the provider panicking at parseLeafCert(certGetResp.ContentBytes). On the
// UNFIXED code this panics (the deferred recover converts the panic into a test
// failure); on the fixed code Update returns with
// response.Diagnostics.HasError() == true and the diagnostic summary emitted by
// hasAPIErrors (ERR_SUMMARY_CERTIFICATE_RESOURCE_READ).
//
// Note: the second `certGetResp == nil` guard in Update is belt-and-suspenders
// for a (nil, nil) GET response. That is NOT reproducible through this httptest
// harness — every 200 yields a non-nil *GetCertificateResponse, and the only
// nil-data branch returns a non-nil error — so that guard (and its
// ERR_SUMMARY_CERTIFICATE_RESOURCE_UPDATE summary) is not directly exercised
// here.
func TestUnitKeyfactorCertificateResource_UpdateNilGetResponse(t *testing.T) {
	ctx := context.Background()

	// httptest server: every request under /KeyfactorAPI/Certificates returns
	// HTTP 500 so GetCertificateContext returns (nil, err).
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"Message":"simulated server error"}`))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	// Build the resource schema so we can populate Plan and State.
	schema, sDiags := resourceCommandCertificateType{}.GetSchema(ctx)
	if sDiags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", sDiags)
	}

	// Only the fields load-bearing before the hasAPIErrors early return are
	// populated: a CN (no CSR) so the CSR-vs-CN validation passes, the
	// ID/CertificateId used to build the GET args, CollectionId, and
	// ExpiryWarningDays. The null list/map element types are required for
	// Plan.Set / State.Set to succeed. Fields consumed only after the GET (key
	// password, SAN lists, metadata, owner role, revoke-on-destroy, certificate
	// format) are intentionally omitted — Update returns at hasAPIErrors before
	// they are read.
	nullList := types.List{ElemType: types.StringType, Null: true}
	nullMap := types.Map{ElemType: types.StringType, Null: true}

	plan := CommandCertificate{
		ID:                types.String{Value: "845070"},
		CertificateId:     types.Int64{Value: 845070},
		CommonName:        types.String{Value: "tf-unit-nil-update.example.com"},
		CSR:               types.String{Null: true},
		CollectionId:      types.Int64{Value: 0},
		ExpiryWarningDays: types.Int64{Null: true},
		DNSSANs:           nullList,
		IPSANs:            nullList,
		URISANs:           nullList,
		Metadata:          nullMap,
	}

	state := plan

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCommandCertificate{p: provider{configured: true, client: client}}

	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	// The whole point of this regression test: Update must NOT panic when
	// GetCertificateContext returns (nil, err). Convert any panic into a clear
	// test failure so the unfixed code is observably red.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("Update panicked (nil-deref regression): %v", rec)
			}
		}()
		r.Update(ctx, req, resp)
	}()

	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected Update to surface a diagnostic error when the certificate GET fails, got none")
	}

	// Sanity: the diagnostic should mention the certificate read failure, not a
	// generic panic message.
	var found bool
	for _, d := range resp.Diagnostics.Errors() {
		if d.Summary() == ERR_SUMMARY_CERTIFICATE_RESOURCE_READ {
			found = true
			break
		}
	}
	if !found {
		t.Logf("diagnostics: %+v", resp.Diagnostics)
		t.Fatalf("expected a %q error diagnostic", ERR_SUMMARY_CERTIFICATE_RESOURCE_READ)
	}
}

// TestUnitKeyfactorCertificateResource_OwnerRoleNameUndeclaredNoSpuriousChange
// is a regression test for owner_role_name being wiped on every Update when
// the config never declares it. owner_role_name was schema'd Optional-only
// (not Computed), so Read()'s unconditional overwrite with server truth was
// itself a source of "inconsistent result after apply", and Update() diffed
// plan.OwnerRoleName.Value (empty string when undeclared) against
// state.OwnerRoleName.Value (a real role name), firing
// ChangeCertificateOwnerRole with an explicit empty NewRoleName and clearing
// an assignment the user never touched via Terraform.
//
// The fix makes owner_role_name Optional+Computed with UseStateForUnknown (so
// an undeclared plan carries the prior state value forward, matching every
// other Optional+Computed scalar in this resource) and moves the Update()
// diff decision into certificateOwnerRoleChanged, which explicitly refuses to
// report a change when the plan value is Null/Unknown.
func TestUnitKeyfactorCertificateResource_OwnerRoleNameUndeclaredNoSpuriousChange(t *testing.T) {
	state := CommandCertificate{
		OwnerRoleName: types.String{Value: "ExistingOwnerRole"},
	}

	// Plan never declared owner_role_name: Null, not the zero-value "".
	planUndeclared := CommandCertificate{
		OwnerRoleName: types.String{Null: true},
	}
	if certificateOwnerRoleChanged(planUndeclared, state) {
		t.Fatalf("expected no owner role change when plan never declares owner_role_name, but certificateOwnerRoleChanged returned true")
	}

	// Plan explicitly sets a different owner_role_name: the change must fire.
	planChanged := CommandCertificate{
		OwnerRoleName: types.String{Value: "NewOwnerRole"},
	}
	if !certificateOwnerRoleChanged(planChanged, state) {
		t.Fatalf("expected an owner role change when plan explicitly sets a different owner_role_name, but certificateOwnerRoleChanged returned false")
	}

	// Plan explicitly re-declares the same value as state: no change.
	planUnchanged := CommandCertificate{
		OwnerRoleName: types.String{Value: "ExistingOwnerRole"},
	}
	if certificateOwnerRoleChanged(planUnchanged, state) {
		t.Fatalf("expected no owner role change when plan explicitly matches state, but certificateOwnerRoleChanged returned true")
	}
}

// TestUnitKeyfactorCertificateResource_OwnerRoleNameIsComputed guards the
// schema half of the same fix: owner_role_name must be Optional+Computed with
// UseStateForUnknown so Read() overwriting it with server truth doesn't
// itself produce "Provider produced inconsistent result after apply" for an
// attribute the config never set.
func TestUnitKeyfactorCertificateResource_OwnerRoleNameIsComputed(t *testing.T) {
	ctx := context.Background()
	schema, diags := resourceCommandCertificateType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", diags)
	}

	attr, ok := schema.Attributes["owner_role_name"]
	if !ok {
		t.Fatalf("expected schema attribute %q to exist", "owner_role_name")
	}
	if !attr.Optional || !attr.Computed {
		t.Fatalf("owner_role_name: expected Optional+Computed, got Optional=%v Computed=%v", attr.Optional, attr.Computed)
	}

	found := false
	for _, m := range attr.PlanModifiers {
		if _, ok := m.(tfsdk.UseStateForUnknownModifier); ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("owner_role_name: expected UseStateForUnknown plan modifier, but none was found (modifiers: %+v)", attr.PlanModifiers)
	}
}

// TestUnitCertificateOwnerRoleClearSendsEmptyPayload is a regression test for
// declaratively clearing owner_role_name (G1). Per the verified live Command
// v25.5 behavior (Swagger doc: "If removing the owner, leave both empty" --
// confirmed with a real PUT: HTTP 204, subsequent GET shows
// OwnerRoleId/OwnerRoleName null), the wire payload for clearing ownership
// must omit BOTH NewRoleId and NewRoleName -- i.e. `{}`.
//
// Before this fix, ownerChangeRequestForPlan("") reproduced the historical
// inline Update() logic: strconv.Atoi("") fails, so it fell into the
// "treat as name" branch and sent {"NewRoleName":""} -- a non-empty pointer
// to an empty string is NOT omitted by Go's `omitempty` (only a nil pointer
// is), so this is NOT the verified clear payload and is an unverified,
// possibly-rejected wire shape.
//
// This drives the real HTTP call through api.Client.ChangeCertificateOwnerRole
// so the assertion exercises actual JSON-over-the-wire shaping, not just the
// in-memory struct.
func TestUnitCertificateOwnerRoleClearSendsEmptyPayload(t *testing.T) {
	const certID = 845070

	var capturedBody string
	var sawRequest bool
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/KeyfactorAPI/Certificates/%d/Owner", certID), func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		body, _ := io.ReadAll(r.Body)
		capturedBody = strings.TrimSpace(string(body))
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newCertUpdateMockClient(server)

	state := CommandCertificate{OwnerRoleName: types.String{Value: "Administrator"}}
	plan := CommandCertificate{OwnerRoleName: types.String{Value: ""}}

	if !certificateOwnerRoleChanged(plan, state) {
		t.Fatalf("expected certificateOwnerRoleChanged to report a change when explicitly clearing a declared owner")
	}

	ownerRequest := ownerChangeRequestForPlan(plan.OwnerRoleName.Value)
	if err := client.ChangeCertificateOwnerRole(certID, ownerRequest); err != nil {
		t.Fatalf("ChangeCertificateOwnerRole returned error: %v", err)
	}

	if !sawRequest {
		t.Fatalf("expected a PUT to /Certificates/%d/Owner, got none", certID)
	}
	if capturedBody != "{}" {
		t.Fatalf("expected the verified clear payload {} (both NewRoleId/NewRoleName omitted), got %q", capturedBody)
	}
}

// TestUnitCertificateOwnerRoleClearNoopWhenAlreadyEmpty verifies that
// declaring owner_role_name = "" against a certificate that already has no
// owner (prior state Null, server-value "") is a no-op: certificateOwnerRoleChanged
// must not report a change, so Update never calls the owner endpoint at all.
func TestUnitCertificateOwnerRoleClearNoopWhenAlreadyEmpty(t *testing.T) {
	state := CommandCertificate{OwnerRoleName: types.String{Null: true}}
	plan := CommandCertificate{OwnerRoleName: types.String{Value: ""}}

	if certificateOwnerRoleChanged(plan, state) {
		t.Fatalf("expected no owner role change when clearing an already-empty owner, but certificateOwnerRoleChanged returned true")
	}
}

// TestUnitCertificateReadKeepsOwnerClearSentinel is a regression test for
// sentinel stability (attribute contract item 4) on owner_role_name Read.
// When the server reports no owner (serverValue == "") AND the prior state
// itself declared the "" clear sentinel, Read must keep "" (Known,
// non-null) rather than collapsing to Null -- otherwise the very next plan
// would show a spurious `"" -> null -> ""` diff forever, since config still
// declares owner_role_name = "".
//
// On the unfixed keepStringSentinel (which unconditionally applies
// isNullString), an empty serverValue always collapses to Null regardless of
// the prior sentinel, so this is red before the fix.
func TestUnitCertificateReadKeepsOwnerClearSentinel(t *testing.T) {
	prior := types.String{Value: ""}
	got := keepStringSentinel("", prior)
	if got.Null || got.Value != "" {
		t.Fatalf("expected the \"\" clear sentinel to be preserved (Value=\"\", Null=false), got %+v", got)
	}
}

// TestUnitCertificateReadSurfacesOwnerDriftOverSentinel verifies the other
// half of sentinel stability: if a REAL owner appears out-of-band (server
// reports a non-empty value) while prior state held the "" clear sentinel,
// Read must surface that as drift -- never mask it with the stale sentinel.
func TestUnitCertificateReadSurfacesOwnerDriftOverSentinel(t *testing.T) {
	prior := types.String{Value: ""}
	got := keepStringSentinel("SomeRole", prior)
	if got.Null || got.Value != "SomeRole" {
		t.Fatalf("expected server-side drift to be surfaced (Value=\"SomeRole\", Null=false), got %+v", got)
	}
}
