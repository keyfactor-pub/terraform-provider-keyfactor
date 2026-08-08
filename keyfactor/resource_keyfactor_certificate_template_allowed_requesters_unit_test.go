package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	sdkclient "github.com/Keyfactor/keyfactor-go-client-sdk/v24"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Unit tests — keyfactor_certificate_template Update() dropping
// allowed_requesters (issue #195)
//
// Live repro (provider v2.9.1 -> Command 25.5): a keyfactor_certificate_template
// update that doesn't declare allowed_requesters cleared the template's
// AllowedRequesters server-side. allowed_requesters is Optional but NOT
// Computed (no UseStateForUnknown), so an undeclared attribute plans to Null
// -- not "leave unchanged" -- and buildTemplateUpdateRequest skips Null
// attributes entirely. PUT /Templates is a full-replace endpoint, so the
// resulting request cleared a real requester list on every update that
// didn't happen to touch allowed_requesters. On Command 25.x this then
// surfaces downstream as "Enrollment Pattern needs to have at least one
// associated role" (0xA011000F) once the list is empty -- after the payload
// already dropped the requesters that would have prevented it.
//
// The fix (preserveAllowedRequesters, called from Update() before
// buildTemplateUpdateRequest) does a read-modify-write: when the plan doesn't
// declare allowed_requesters, it fetches the template fresh via
// GET /Templates/{id} and carries that CURRENT value forward -- not this
// resource's own prior Terraform state, which can itself be stale because
// keyfactor_template_role_binding mutates the same field out-of-band via its
// own PUT calls (see #190 / addAllowedRequesterToTemplate).
//
// These tests drive resourceCertificateTemplate.Update() directly against a
// local httptest server standing in for Command (there is no VCR cassette
// here: recording one would require a mutating PUT against a live lab), and
// assert the PUT /Templates payload's AllowedRequesters.
// ---------------------------------------------------------------------------

// templateUpdateMockAuthConfig implements the AuthConfig interface used by
// the keyfactor-go-client-sdk/v24 API client, pointing it at a local httptest
// server instead of a real Command instance.
type templateUpdateMockAuthConfig struct {
	server *httptest.Server
}

func (m *templateUpdateMockAuthConfig) GetServerConfig() *auth_providers.Server {
	u, err := url.Parse(m.server.URL)
	host := m.server.URL
	if err == nil && u.Host != "" {
		host = u.Host
	}
	return &auth_providers.Server{
		Host:          host,
		APIPath:       "KeyfactorAPI",
		SkipTLSVerify: true,
	}
}

func (m *templateUpdateMockAuthConfig) GetHttpClient() (*http.Client, error) {
	return m.server.Client(), nil
}

func (m *templateUpdateMockAuthConfig) Authenticate() error       { return nil }
func (m *templateUpdateMockAuthConfig) GetCommandVersion() string { return "25.5.0.0" }

func newTemplateUpdateSDKClient(server *httptest.Server) *sdkclient.APIClient {
	return sdkclient.NewAPIClientWithAuth(&templateUpdateMockAuthConfig{server: server})
}

// blankTemplateState returns a KeyfactorCertificateTemplateState with every
// attribute explicitly set to a well-typed Null/empty value, matching the
// full schema from resourceCertificateTemplateType.GetSchema. This is a
// test-only helper so callers can flip just the field(s) under test without
// hand-populating every field, while still producing a struct that
// tfsdk.Plan.Set / tfsdk.State.Set can serialize without a schema mismatch.
func blankTemplateState() KeyfactorCertificateTemplateState {
	nullStr := types.String{Null: true}
	nullBool := types.Bool{Null: true}
	nullInt := types.Int64{Null: true}
	nullStrList := types.List{Null: true, ElemType: types.StringType}
	return KeyfactorCertificateTemplateState{
		ID:                        nullInt,
		CommonName:                nullStr,
		TemplateName:              nullStr,
		DisplayName:               nullStr,
		OID:                       nullStr,
		KeySize:                   nullStr,
		KeyType:                   nullStr,
		KeyTypes:                  nullStr,
		ForestRoot:                nullStr,
		ConfigurationTenant:       nullStr,
		KeyArchival:               nullBool,
		FriendlyName:              nullStr,
		KeyRetention:              nullInt,
		KeyRetentionDays:          nullInt,
		AllowedEnrollmentTypes:    nullInt,
		UseAllowedRequesters:      nullBool,
		AllowedRequesters:         nullStrList,
		RequiresApproval:          nullBool,
		AllowOneClickRenewals:     nullBool,
		KeyUsage:                  nullInt,
		TemplatePolicy:            nil,
		TemplateRegexes:           nil,
		TemplateDefaults:          nil,
		EnrollmentFields:          nil,
		MetadataFields:            nil,
		ExtendedKeyUsages:         nil,
		KeyAlgorithms:             nil,
		Manageability:             nullInt,
		CertificateCleanupEnabled: nullBool,
		TimeAfterExpiration:       nullInt,
		TimeAfterExpirationUnits:  nullInt,
		DeleteWithArchivedKey:     nullBool,
	}
}

func templateSchema(t *testing.T, ctx context.Context) tfsdk.Schema {
	t.Helper()
	schema, diags := resourceCertificateTemplateType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema returned diagnostics: %+v", diags)
	}
	return schema
}

// newTemplateUpdateTestServer returns an httptest server that answers
// GET /Templates/{id} with a canned template whose CURRENT AllowedRequesters
// includes a role added out-of-band (simulating a keyfactor_template_role_binding
// change since this resource's own last Read), and captures the body of any
// PUT /Templates request into *capturedPUTBody.
func newTemplateUpdateTestServer(t *testing.T, currentAllowedRequesters []string, capturedPUTBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(4)
			resp.SetCommonName("TestTemplate")
			resp.SetTemplateName("Test Template")
			resp.SetUseAllowedRequesters(len(currentAllowedRequesters) > 0)
			resp.AllowedRequesters = currentAllowedRequesters
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode GET response: %v", err)
			}
		case r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read PUT request body: %v", err)
			}
			*capturedPUTBody = body
			// Echo back a minimal, decodable response so templateResponseToState
			// doesn't choke -- carry AllowedRequesters through if present on the
			// wire so the resulting state is self-consistent.
			var onWire map[string]interface{}
			_ = json.Unmarshal(body, &onWire)
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(4)
			resp.SetCommonName("TestTemplate")
			resp.SetTemplateName("Test Template")
			if ar, ok := onWire["AllowedRequesters"].([]interface{}); ok {
				var roles []string
				for _, r := range ar {
					if s, ok := r.(string); ok {
						roles = append(roles, s)
					}
				}
				resp.AllowedRequesters = roles
				resp.SetUseAllowedRequesters(len(roles) > 0)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("failed to encode PUT response: %v", err)
			}
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitCertificateTemplateUpdatePreservesAllowedRequesters is the direct
// regression test for issue #195: an Update() whose plan does NOT declare
// allowed_requesters (Null, simulating an omitted HCL attribute) must not
// send an empty/absent AllowedRequesters on the PUT /Templates payload. It
// must instead carry forward the template's CURRENT server-side value,
// fetched fresh via GET -- proven here by seeding the fake server's GET
// response with a role ("OutOfBandRole") that is NOT present in this
// resource's own prior Terraform state, simulating a
// keyfactor_template_role_binding change made since this resource's last Read.
func TestUnitCertificateTemplateUpdatePreservesAllowedRequesters(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	// The server's CURRENT AllowedRequesters includes a role this resource's
	// own prior state has never seen.
	server := newTemplateUpdateTestServer(t, []string{"ExistingRole", "OutOfBandRole"}, &putBody)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	// Prior local state: stale relative to the server (only knows about
	// ExistingRole).
	state := blankTemplateState()
	state.ID = types.Int64{Value: 4}
	state.UseAllowedRequesters = types.Bool{Value: true}
	state.AllowedRequesters = stringSliceToTfList([]string{"ExistingRole"})

	// Plan: config doesn't declare allowed_requesters at all (Null) -- the
	// exact shape that triggered issue #195. use_allowed_requesters is
	// Optional+Computed, so a real plan would carry the prior state value
	// forward via UseStateForUnknown; simulate that here too.
	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 4}
	plan.UseAllowedRequesters = types.Bool{Value: true}
	plan.AllowedRequesters = types.List{Null: true, ElemType: types.StringType}
	plan.RequiresApproval = types.Bool{Value: false}

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	if len(putBody) == 0 {
		t.Fatal("no PUT /Templates request was captured")
	}
	var onWire map[string]interface{}
	if err := json.Unmarshal(putBody, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}

	requestersRaw, ok := onWire["AllowedRequesters"]
	if !ok || requestersRaw == nil {
		t.Fatalf(
			"PUT /Templates payload has no AllowedRequesters -- this reproduces issue #195: "+
				"an update that doesn't declare allowed_requesters clears the template's requester list "+
				"server-side. Full payload: %s", putBody,
		)
	}
	requesters, ok := requestersRaw.([]interface{})
	if !ok {
		t.Fatalf("AllowedRequesters on the wire is not a list: %v", requestersRaw)
	}
	got := make(map[string]bool, len(requesters))
	for _, v := range requesters {
		if s, ok := v.(string); ok {
			got[s] = true
		}
	}
	if !got["ExistingRole"] || !got["OutOfBandRole"] {
		t.Fatalf(
			"AllowedRequesters on the wire = %v, want both ExistingRole and OutOfBandRole preserved "+
				"(OutOfBandRole proves the value came from a fresh GET, not this resource's stale prior state)",
			requesters,
		)
	}
	if len(requesters) != 2 {
		t.Errorf("AllowedRequesters on the wire has %d entries, want exactly 2: %v", len(requesters), requesters)
	}
}

// TestUnitCertificateTemplateUpdateDeclaredAllowedRequestersNotOverridden is
// the negative-space companion test: when the plan DOES declare
// allowed_requesters, Update() must send exactly that declared value and
// must NOT perform (or be influenced by) the preservation GET.
func TestUnitCertificateTemplateUpdateDeclaredAllowedRequestersNotOverridden(t *testing.T) {
	ctx := context.Background()

	var putBody []byte
	var getHits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			getHits++
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(4)
			resp.AllowedRequesters = []string{"ShouldNotAppear"}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			putBody = body
			resp := v1.TemplatesTemplateRetrievalResponse{}
			resp.SetId(4)
			resp.AllowedRequesters = []string{"DeclaredRole"}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := templateSchema(t, ctx)

	state := blankTemplateState()
	state.ID = types.Int64{Value: 4}
	state.UseAllowedRequesters = types.Bool{Value: true}
	state.AllowedRequesters = stringSliceToTfList([]string{"OldRole"})

	plan := blankTemplateState()
	plan.ID = types.Int64{Value: 4}
	plan.UseAllowedRequesters = types.Bool{Value: true}
	plan.AllowedRequesters = stringSliceToTfList([]string{"DeclaredRole"})

	planObj := tfsdk.Plan{Schema: schema}
	if d := planObj.Set(ctx, &plan); d.HasError() {
		t.Fatalf("test setup: plan.Set returned diagnostics: %+v", d)
	}
	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceCertificateTemplate{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update returned diagnostics: %+v", resp.Diagnostics)
	}

	if getHits != 0 {
		t.Errorf("expected no preservation GET when allowed_requesters is declared, got %d GET(s)", getHits)
	}

	var onWire map[string]interface{}
	if err := json.Unmarshal(putBody, &onWire); err != nil {
		t.Fatalf("failed to decode PUT request body: %v", err)
	}
	requesters, ok := onWire["AllowedRequesters"].([]interface{})
	if !ok || len(requesters) != 1 || requesters[0] != "DeclaredRole" {
		t.Fatalf("AllowedRequesters on the wire = %v, want exactly [\"DeclaredRole\"]", onWire["AllowedRequesters"])
	}
}
