package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
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

// ---------------------------------------------------------------------------
// Regression tests for the PR #228 review findings (phase-0 hardening, round 3).
// Every test here is network-free: Command is stood in for by an httptest server.
// ---------------------------------------------------------------------------

func stringList(vals ...string) types.List {
	elems := make([]attr.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, types.String{Value: v})
	}
	return types.List{ElemType: types.StringType, Elems: elems}
}

func listStrings(t *testing.T, l types.List) []string {
	t.Helper()
	out := make([]string, 0, len(l.Elems))
	for _, e := range l.Elems {
		out = append(out, e.(types.String).Value)
	}
	return out
}

func emptyState(ctx context.Context, schema tfsdk.Schema) tfsdk.State {
	return tfsdk.State{Schema: schema, Raw: tftypes.NewValue(schema.TerraformType(ctx), nil)}
}

func stateWith(t *testing.T, schema tfsdk.Schema, v interface{}) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	st := emptyState(ctx, schema)
	diags := st.Set(ctx, v)
	require.False(t, diags.HasError(), "building test state: %v", diags)
	return st
}

// templatesServer answers GET Templates/ with the given templates and GET Templates/{id} with
// the matching template, and records the body of any PUT.
func templatesServer(t *testing.T, templates []api.GetTemplateResponse, putBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/KeyfactorAPI/Templates"), "/")
			if trimmed == "" {
				_ = json.NewEncoder(w).Encode(templates)
				return
			}
			for _, tpl := range templates {
				if trimmed == strconv.Itoa(tpl.Id) {
					_ = json.NewEncoder(w).Encode(tpl)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			if putBody != nil {
				*putBody = body
			}
			_ = json.NewEncoder(w).Encode(api.UpdateTemplateResponse{GetTemplateResponse: api.GetTemplateResponse{Id: 4}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

// ---------------------------------------------------------------------------
// Finding 2: template_role_binding Read drops templates that no longer exist.
// ---------------------------------------------------------------------------

func TestUnitTemplateRoleBindingRead_DropsMissingTemplatesFromState(t *testing.T) {
	ctx := context.Background()
	srv := templatesServer(t, []api.GetTemplateResponse{
		{Id: 4, CommonName: "WebServer"},
		{Id: 5, CommonName: "Client"},
	}, nil)
	defer srv.Close()

	res := resourceCertificateTemplateRoleBinding{p: provider{client: newTemplateTestClient(srv)}}
	schema, _ := resourceCertificateTemplateRoleBindingType{}.GetSchema(ctx)
	st := stateWith(t, schema, CertificateTemplateRoleBinding{
		ID:            types.String{Value: "abc"},
		RoleName:      types.String{Value: "Role"},
		TemplateNames: stringList("WebServer", "Gone", "client"),
	})

	resp := &tfsdk.ReadResourceResponse{State: st}
	res.Read(ctx, tfsdk.ReadResourceRequest{State: st}, resp)

	require.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics)
	var got CertificateTemplateRoleBinding
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.Equal(t, []string{"WebServer", "client"}, listStrings(t, got.TemplateNames),
		"a template deleted in Command must be dropped from state so the plan shows the drift")

	var warned bool
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Detail(), "Gone") {
			warned = true
			assert.Equal(t, diag.SeverityWarning, d.Severity())
			assert.NotContains(t, d.Detail(), "WebServer")
		}
	}
	assert.True(t, warned, "a warning naming the dropped template must be emitted: %v", resp.Diagnostics)
}

func TestUnitTemplateRoleBindingRead_AllTemplatesPresentIsUnchanged(t *testing.T) {
	ctx := context.Background()
	srv := templatesServer(t, []api.GetTemplateResponse{{Id: 4, CommonName: "WebServer"}}, nil)
	defer srv.Close()

	res := resourceCertificateTemplateRoleBinding{p: provider{client: newTemplateTestClient(srv)}}
	schema, _ := resourceCertificateTemplateRoleBindingType{}.GetSchema(ctx)
	st := stateWith(t, schema, CertificateTemplateRoleBinding{
		ID:            types.String{Value: "abc"},
		RoleName:      types.String{Value: "Role"},
		TemplateNames: stringList("WebServer"),
	})

	resp := &tfsdk.ReadResourceResponse{State: st}
	res.Read(ctx, tfsdk.ReadResourceRequest{State: st}, resp)

	require.False(t, resp.Diagnostics.HasError())
	assert.Empty(t, resp.Diagnostics)
	var got CertificateTemplateRoleBinding
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.Equal(t, []string{"WebServer"}, listStrings(t, got.TemplateNames))
}

func TestUnitPartitionTemplateNamesByExistence(t *testing.T) {
	templates := []api.GetTemplateResponse{{Id: 1, CommonName: "WebServer"}, {Id: 2, CommonName: "Client"}}
	kept, dropped := partitionTemplateNamesByExistence(templates, []string{"webserver", "Gone", "", "Client"})
	assert.Equal(t, []string{"webserver", "Client"}, kept)
	assert.Equal(t, []string{"Gone", ""}, dropped)
}

// ---------------------------------------------------------------------------
// Finding 6: role_name case-only changes must not force replacement, and the allowed-requester
// bookkeeping must treat role names case-insensitively.
// ---------------------------------------------------------------------------

func roleBindingRoleNameModifierResult(t *testing.T, stateRole, planRole types.String) bool {
	t.Helper()
	ctx := context.Background()
	schema, _ := resourceCertificateTemplateRoleBindingType{}.GetSchema(ctx)
	attrSchema := schema.Attributes["role_name"]
	require.Len(t, attrSchema.PlanModifiers, 1)

	mkObj := func(role types.String) CertificateTemplateRoleBinding {
		return CertificateTemplateRoleBinding{
			ID:            types.String{Value: "abc"},
			RoleName:      role,
			TemplateNames: stringList("WebServer"),
		}
	}
	st := stateWith(t, schema, mkObj(stateRole))
	pl := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, mkObj(planRole)).Raw}
	cfg := tfsdk.Config{Schema: schema, Raw: pl.Raw}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributePath:   path.Root("role_name"),
		Config:          cfg,
		State:           st,
		Plan:            pl,
		AttributeConfig: planRole,
		AttributePlan:   planRole,
		AttributeState:  stateRole,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: planRole}
	attrSchema.PlanModifiers[0].Modify(ctx, req, resp)
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	return resp.RequiresReplace
}

func TestUnitRoleBindingRoleName_CaseOnlyChangeDoesNotReplace(t *testing.T) {
	str := func(s string) types.String { return types.String{Value: s} }
	assert.False(t, roleBindingRoleNameModifierResult(t, str("Role"), str("role")), "case-only change must update in place")
	assert.False(t, roleBindingRoleNameModifierResult(t, str("role"), str("ROLE")), "case-only change must update in place")
	assert.False(t, roleBindingRoleNameModifierResult(t, str("Role"), str("Role")), "no change must not replace")
	assert.True(t, roleBindingRoleNameModifierResult(t, str("Role"), str("OtherRole")), "a different role must replace")
	assert.True(t, roleBindingRoleNameModifierResult(t, str("Role"), types.String{Unknown: true}), "unknown must replace")
}

func TestUnitRoleBindingUpdate_CaseOnlyRoleNameChangeWritesNewCasing(t *testing.T) {
	ctx := context.Background()
	var putBody []byte
	srv := templatesServer(t, []api.GetTemplateResponse{{
		Id: 4, CommonName: "WebServer", UseAllowedRequesters: true, AllowedRequesters: []string{"Role"},
	}}, &putBody)
	defer srv.Close()

	res := resourceCertificateTemplateRoleBinding{p: provider{client: newTemplateTestClient(srv)}}
	schema, _ := resourceCertificateTemplateRoleBindingType{}.GetSchema(ctx)
	st := stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Value: "abc"}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("WebServer"),
	})
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Value: "abc"}, RoleName: types.String{Value: "role"}, TemplateNames: stringList("WebServer"),
	}).Raw}

	resp := &tfsdk.UpdateResourceResponse{State: st}
	res.Update(ctx, tfsdk.UpdateResourceRequest{State: st, Plan: plan}, resp)

	require.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics)
	var got CertificateTemplateRoleBinding
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.Equal(t, "role", got.RoleName.Value, "state must record the new casing")
	assert.Empty(t, putBody, "the role is already an allowed requester (case-insensitively); no template PUT is needed")
}

func TestUnitRemoveRoleFromTemplate_MatchesRoleCaseInsensitively(t *testing.T) {
	var putBody []byte
	srv := templatesServer(t, []api.GetTemplateResponse{{
		Id: 4, CommonName: "WebServer", UseAllowedRequesters: true, AllowedRequesters: []string{"Role", "Other"},
	}}, &putBody)
	defer srv.Close()

	diags := removeRoleFromTemplate(context.Background(), newTemplateTestClient(srv), "role", 4)
	require.False(t, diags.HasError(), "%v", diags)

	var sent api.UpdateTemplateArg
	require.NoError(t, json.Unmarshal(putBody, &sent))
	require.NotNil(t, sent.AllowedRequesters)
	assert.Equal(t, []string{"Other"}, *sent.AllowedRequesters, "role removal must match the role name case-insensitively")
}

func TestUnitAddAllowedRequester_AlreadyPresentDifferentCaseIsNoOp(t *testing.T) {
	var putBody []byte
	srv := templatesServer(t, []api.GetTemplateResponse{{
		Id: 4, CommonName: "WebServer", UseAllowedRequesters: true, AllowedRequesters: []string{"Role"},
	}}, &putBody)
	defer srv.Close()

	diags := addAllowedRequesterToTemplate(context.Background(), newTemplateTestClient(srv), "role", "4")
	require.False(t, diags.HasError(), "%v", diags)
	assert.Empty(t, putBody, "adding an already-present role (different case) must not PUT a duplicate entry")
}

func TestUnitFindTemplateRoleAttachments_MatchesRoleCaseInsensitively(t *testing.T) {
	srv := templatesServer(t, []api.GetTemplateResponse{
		{Id: 4, CommonName: "WebServer", UseAllowedRequesters: true, AllowedRequesters: []string{"Role"}},
		{Id: 5, CommonName: "Client", UseAllowedRequesters: true, AllowedRequesters: []string{"Other"}},
	}, nil)
	defer srv.Close()

	diags, ids := findTemplateRoleAttachments(context.Background(), newTemplateTestClient(srv), "ROLE")
	require.False(t, diags.HasError(), "%v", diags)
	assert.Equal(t, []interface{}{4}, ids)
}

// ---------------------------------------------------------------------------
// Findings 3, 4, 5: OAuth security role / claim data sources must not panic on sparse
// or failed Command responses.
// ---------------------------------------------------------------------------

func roleDataSourceConfig(t *testing.T, ctx context.Context, name string) (tfsdk.Schema, tfsdk.Config) {
	t.Helper()
	schema, d := dataSourceOAuthSecurityRoleType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	st := stateWith(t, schema, OAuthSecurityRole{
		ID:              types.Int64{Null: true},
		Name:            types.String{Value: name},
		Description:     types.String{Null: true},
		EmailAddress:    types.String{Null: true},
		Immutable:       types.Bool{Null: true},
		Permissions:     types.Set{Null: true, ElemType: types.StringType},
		PermissionSetId: types.String{Null: true},
	})
	return schema, tfsdk.Config{Schema: schema, Raw: st.Raw}
}

// Finding 3: when the by-ID request fails before any HTTP response exists (the SDK returns a nil
// *http.Response), the data source must report an error diagnostic, not panic.
func TestUnitRoleDataSourceRead_TransportErrorOnByIdRequestDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"Id": 7, "Name": "Admins"}]`))
			return
		}
		// Drop the connection without a response.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("hijacking not supported")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	schema, cfg := roleDataSourceConfig(t, ctx, "Admins")
	ds := dataSourceOauthSecurityRole{p: provider{sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() { ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: cfg}, resp) })
	assert.True(t, resp.Diagnostics.HasError(), "a failed by-ID read must surface as an error diagnostic")
}

// Finding 5: a role returned without an Id must produce an error, not a nil dereference.
func TestUnitRoleDataSourceRead_RoleWithoutIdIsAnError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Name": "Admins"}]`))
	}))
	defer srv.Close()

	schema, cfg := roleDataSourceConfig(t, ctx, "Admins")
	ds := dataSourceOauthSecurityRole{p: provider{sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() { ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: cfg}, resp) })
	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Detail(), "without an ID")
}

func TestUnitRequireSecurityRoleID(t *testing.T) {
	_, err := requireSecurityRoleID("Admins", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Admins")
	id := int32(9)
	got, err := requireSecurityRoleID("Admins", &id)
	require.NoError(t, err)
	assert.Equal(t, int32(9), got)
}

func TestUnitReadErrorResponseBody_NilSafe(t *testing.T) {
	assert.Equal(t, "", readErrorResponseBody(nil))
	assert.Equal(t, "", readErrorResponseBody(&http.Response{}))
	assert.Equal(t, "boom", readErrorResponseBody(&http.Response{Body: io.NopCloser(strings.NewReader("boom"))}))
}

// Finding 4: a claim returned without Id, Description or ClaimType must be mapped to null
// values (or the configured value for Required attributes), not dereferenced.
func TestUnitClaimDataSourceRead_SparseClaimDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ClaimValue": "alice", "Provider": {"AuthenticationScheme": "System"}}]`))
	}))
	defer srv.Close()

	schema, d := dataSourceOAuthSecurityClaimType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	cfgState := stateWith(t, schema, OAuthSecurityClaim{
		ID:                           types.Int64{Null: true},
		Description:                  types.String{Null: true},
		ClaimType:                    types.String{Value: "OAuthSubject"},
		ClaimValue:                   types.String{Value: "Alice"},
		Provider:                     types.Object{Null: true, AttrTypes: OAuthSecurityClaimAuthenticationProviderType},
		ProviderAuthenticationScheme: types.String{Value: "System"},
	})
	ds := dataSourceOauthSecurityClaim{p: provider{sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() {
		ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: tfsdk.Config{Schema: schema, Raw: cfgState.Raw}}, resp)
	})
	require.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics)

	var got OAuthSecurityClaim
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.True(t, got.ID.Null, "missing Id must be null")
	assert.True(t, got.Description.Null, "missing Description must be null")
	assert.Equal(t, "OAuthSubject", got.ClaimType.Value, "missing ClaimType falls back to the configured value")
	assert.Equal(t, "Alice", got.ClaimValue.Value, "claim_value keeps the configured casing")
	assert.Equal(t, "System", got.ProviderAuthenticationScheme.Value)
}

// ---------------------------------------------------------------------------
// Finding 7: include_private_key must be known at plan time for an existing deployment.
// ---------------------------------------------------------------------------

func TestUnitDeploymentModifyPlan_UnknownIncludePrivateKeyIsAnError(t *testing.T) {
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())

	mk := func(ipk types.Bool) CommandCertificateDeployment {
		return CommandCertificateDeployment{
			ID:                types.String{Value: "id"},
			CertificateId:     types.Int64{Value: 1},
			CertificateAlias:  types.String{Null: true},
			StoreId:           types.String{Value: "store"},
			KeyPassword:       types.String{Null: true},
			JobParameters:     types.Map{Null: true, ElemType: types.StringType},
			Overwrite:         types.Bool{Null: true},
			Redeploy:          types.Bool{Null: true},
			SkipRemoval:       types.Bool{Null: true},
			IncludePrivateKey: ipk,
		}
	}
	run := func(state, plan types.Bool) *tfsdk.ModifyResourcePlanResponse {
		st := stateWith(t, schema, mk(state))
		pl := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, mk(plan)).Raw}
		resp := &tfsdk.ModifyResourcePlanResponse{Plan: pl}
		resourceCommandCertificateDeployment{}.ModifyPlan(ctx, tfsdk.ModifyResourcePlanRequest{State: st, Plan: pl}, resp)
		return resp
	}

	resp := run(types.Bool{Value: true}, types.Bool{Unknown: true})
	require.True(t, resp.Diagnostics.HasError(), "an unknown include_private_key must be rejected at plan time")
	assert.Contains(t, resp.Diagnostics[0].Detail(), "must be known at plan time")

	// Known values are unaffected.
	assert.False(t, run(types.Bool{Value: true}, types.Bool{Value: true}).Diagnostics.HasError())
	assert.False(t, run(types.Bool{Null: true}, types.Bool{Value: true}).Diagnostics.HasError())
}

// ---------------------------------------------------------------------------
// Findings 8 and 9: the claim and role selectors share one matching helper.
// ---------------------------------------------------------------------------

func TestUnitPickPreferExactCase(t *testing.T) {
	type item struct{ key string }
	cand := func(i *item) (string, bool) { return i.key, i.key != "skip" }

	items := []item{{"alice"}, {"Alice"}, {"ALICE"}}
	got, folded, n := pickPreferExactCase(items, "Alice", cand)
	require.NotNil(t, got)
	assert.Equal(t, "Alice", got.key, "exact case wins over earlier case-insensitive hits")
	assert.False(t, folded, "an exact-case match is not flagged")
	assert.Equal(t, 0, n)

	got, folded, n = pickPreferExactCase([]item{{"alice"}}, "ALICE", cand)
	require.NotNil(t, got)
	assert.True(t, folded, "a case-insensitive-only match is flagged")
	assert.Equal(t, 0, n, "a returned item is never ambiguous")

	got, folded, n = pickPreferExactCase([]item{{"alice"}, {"aLiCe"}}, "ALICE", cand)
	assert.Nil(t, got)
	assert.False(t, folded)
	assert.Equal(t, 2, n, "multiple case-insensitive hits with no exact match are ambiguous")

	got, folded, n = pickPreferExactCase([]item{{"skip"}, {"bob"}}, "skip", cand)
	assert.Nil(t, got, "ineligible items are ignored")
	assert.False(t, folded)
	assert.Equal(t, 0, n)
}
