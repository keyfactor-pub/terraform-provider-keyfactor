package keyfactor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// ---- #8: one template-name matching rule. ----

func TestUnitFindTemplateByName(t *testing.T) {
	templates := []api.GetTemplateResponse{{Id: 1, CommonName: "WebServer"}, {Id: 2, CommonName: "Client"}}
	got := findTemplateByName(templates, "webserver")
	require.NotNil(t, got)
	assert.Equal(t, 1, got.Id)
	assert.Nil(t, findTemplateByName(templates, "Gone"))
	assert.Nil(t, findTemplateByName(templates, ""), "an empty name never matches")
	assert.Nil(t, findTemplateByName(nil, "WebServer"))

	// verifyTemplateNames and partitionTemplateNamesByExistence agree on every name.
	names := []string{"webserver", "CLIENT", "Gone"}
	ids, diags := verifyTemplateNames(context.Background(), templates, names, templateNameSideState)
	kept, dropped := partitionTemplateNamesByExistence(templates, names)
	assert.Equal(t, []int{1, 2}, ids)
	assert.Equal(t, []string{"webserver", "CLIENT"}, kept)
	assert.Equal(t, []string{"Gone"}, dropped)
	assert.Len(t, diags, 1)
}

func TestUnitVerifyTemplateNames(t *testing.T) {
	templates := []api.GetTemplateResponse{{Id: 1, CommonName: "WebServer"}, {Id: 2, CommonName: "Client"}}
	ctx := context.Background()

	// Found names resolve case-insensitively on both sides, with no diagnostics.
	for _, side := range []templateNameSide{templateNameSidePlan, templateNameSideState} {
		ids, diags := verifyTemplateNames(ctx, templates, []string{"webserver", "CLIENT"}, side)
		assert.Equal(t, []int{1, 2}, ids)
		assert.Empty(t, diags)
	}

	// Missing template: plan side is an error.
	ids, diags := verifyTemplateNames(ctx, templates, []string{"WebServer", "Gone"}, templateNameSidePlan)
	assert.Equal(t, []int{1}, ids)
	assert.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityError))
	assert.Equal(t, 0, countDiagsBySeverity(diags, diag.SeverityWarning))

	// Missing template: state side is a warning, the name is skipped, and the rest still resolve.
	ids, diags = verifyTemplateNames(ctx, templates, []string{"WebServer", "Gone"}, templateNameSideState)
	assert.Equal(t, []int{1}, ids)
	assert.Equal(t, 0, countDiagsBySeverity(diags, diag.SeverityError))
	assert.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityWarning))

	// Empty name is exactly one error on both sides (no extra not-found diagnostic).
	for _, side := range []templateNameSide{templateNameSidePlan, templateNameSideState} {
		ids, diags = verifyTemplateNames(ctx, templates, []string{""}, side)
		assert.Empty(t, ids)
		assert.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityError))
		assert.Equal(t, 0, countDiagsBySeverity(diags, diag.SeverityWarning))
	}
}

// F5: a failed template read in removeRoleFromTemplate must return the error, not dereference the
// nil template.
func TestUnitRemoveRoleFromTemplate_TemplateReadErrorIsReturnedWithoutPanic(t *testing.T) {
	var putBody []byte
	srv := templatesServer(t, []api.GetTemplateResponse{{Id: 4, CommonName: "WebServer"}}, &putBody)
	defer srv.Close()

	var diags diag.Diagnostics
	require.NotPanics(t, func() {
		diags = removeRoleFromTemplate(context.Background(), newTemplateTestClient(srv), "Role", 99) // 99 does not exist -> 404
	})
	require.True(t, diags.HasError())
	assert.Contains(t, diags.Errors()[0].Summary(), "Error fetching template")
	assert.Empty(t, putBody, "no template update may be sent when the template could not be read")
}

// F5 (same pattern in addAllowedRequesterToTemplate): when the template list cannot be read while
// resolving a template name, return that error alone instead of falling through to further calls.
func TestUnitAddAllowedRequester_TemplateListErrorIsTheOnlyError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var diags diag.Diagnostics
	require.NotPanics(t, func() {
		diags = addAllowedRequesterToTemplate(context.Background(), newTemplateTestClient(srv), "Role", "WebServer")
	})
	require.True(t, diags.HasError())
	assert.Len(t, diags.Errors(), 1, "only the template list error is expected: %v", diags)
	assert.Contains(t, diags.Errors()[0].Summary(), "Error fetching templates")
}

// F6: a role that is listed in AllowedRequesters while UseAllowedRequesters is false grants
// nothing, so it is not "already present": the template must be updated to enforce the list, keeping
// the existing entries and not duplicating the role.
func TestUnitAddAllowedRequester_ListedButNotEnforcedEnablesEnforcement(t *testing.T) {
	var putBody []byte
	srv := templatesServer(t, []api.GetTemplateResponse{{
		Id: 4, CommonName: "WebServer", UseAllowedRequesters: false, AllowedRequesters: []string{"Role", "Other"},
	}}, &putBody)
	defer srv.Close()

	diags := addAllowedRequesterToTemplate(context.Background(), newTemplateTestClient(srv), "role", "4")
	require.False(t, diags.HasError(), "%v", diags)
	require.NotEmpty(t, putBody, "the template must be updated to turn allowed-requester enforcement on")

	var sent api.UpdateTemplateArg
	require.NoError(t, json.Unmarshal(putBody, &sent))
	require.NotNil(t, sent.UseAllowedRequesters)
	assert.True(t, *sent.UseAllowedRequesters)
	require.NotNil(t, sent.AllowedRequesters)
	assert.Equal(t, []string{"Role", "Other"}, *sent.AllowedRequesters, "the existing list is kept as is, with no duplicate entry")
}

// A role that is not listed at all is appended and enforcement is switched on.
func TestUnitAddAllowedRequester_NotListedIsAppendedAndEnforced(t *testing.T) {
	var putBody []byte
	srv := templatesServer(t, []api.GetTemplateResponse{{
		Id: 4, CommonName: "WebServer", UseAllowedRequesters: false, AllowedRequesters: []string{"Other"},
	}}, &putBody)
	defer srv.Close()

	diags := addAllowedRequesterToTemplate(context.Background(), newTemplateTestClient(srv), "Role", "4")
	require.False(t, diags.HasError(), "%v", diags)

	var sent api.UpdateTemplateArg
	require.NoError(t, json.Unmarshal(putBody, &sent))
	require.NotNil(t, sent.UseAllowedRequesters)
	assert.True(t, *sent.UseAllowedRequesters)
	require.NotNil(t, sent.AllowedRequesters)
	assert.Equal(t, []string{"Other", "Role"}, *sent.AllowedRequesters)
}

// F11: Delete must stop with an error when the prior state cannot be read, instead of carrying on
// with an empty role name and template list.
func TestUnitTemplateRoleBindingDelete_UnreadableStateIsAnErrorAndMakesNoCalls(t *testing.T) {
	ctx := context.Background()
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	schema, _ := resourceCertificateTemplateRoleBindingType{}.GetSchema(ctx)
	badState := tfsdk.State{Schema: schema, Raw: tftypes.NewValue(tftypes.String, "not an object")}
	res := resourceCertificateTemplateRoleBinding{p: provider{client: newTemplateTestClient(srv)}}
	resp := &tfsdk.DeleteResourceResponse{State: badState}

	require.NotPanics(t, func() { res.Delete(ctx, tfsdk.DeleteResourceRequest{State: badState}, resp) })
	assert.True(t, resp.Diagnostics.HasError(), "an unreadable prior state must be an error")
	assert.Zero(t, atomic.LoadInt32(&calls), "no Command call may be made without a readable state")
}

// ---------------------------------------------------------------------------
// Class C/D: the binding only changes what has to change, with one id format.
// ---------------------------------------------------------------------------

// templatePut is one PUT /Templates request as seen by statefulTemplatesServer.
type templatePut struct {
	ID                   int
	AllowedRequesters    []string
	UseAllowedRequesters bool
}

// statefulTemplatesServer is a fake Command whose templates change when they are PUT, so a sequence
// of calls can be asserted end to end. puts records every PUT in order; templates is the live state.
type statefulTemplates struct {
	mu        sync.Mutex
	templates map[int]*api.GetTemplateResponse
	puts      []templatePut
}

func (s *statefulTemplates) snapshot(id int) api.GetTemplateResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.templates[id]
}

func (s *statefulTemplates) putIDs() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []int
	for _, p := range s.puts {
		ids = append(ids, p.ID)
	}
	return ids
}

func newStatefulTemplatesServer(t *testing.T, templates ...api.GetTemplateResponse) (*statefulTemplates, *httptest.Server) {
	t.Helper()
	st := &statefulTemplates{templates: map[int]*api.GetTemplateResponse{}}
	for i := range templates {
		tpl := templates[i]
		st.templates[tpl.Id] = &tpl
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/KeyfactorAPI/Templates"), "/")
			if trimmed == "" {
				var all []api.GetTemplateResponse
				for _, tpl := range st.templates {
					all = append(all, *tpl)
				}
				sort.Slice(all, func(i, j int) bool { return all[i].Id < all[j].Id })
				_ = json.NewEncoder(w).Encode(all)
				return
			}
			id, _ := strconv.Atoi(trimmed)
			tpl, ok := st.templates[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(tpl)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var sent api.UpdateTemplateArg
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Errorf("bad PUT body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			put := templatePut{ID: sent.Id}
			if sent.AllowedRequesters != nil {
				put.AllowedRequesters = *sent.AllowedRequesters
			}
			if sent.UseAllowedRequesters != nil {
				put.UseAllowedRequesters = *sent.UseAllowedRequesters
			}
			st.puts = append(st.puts, put)
			if tpl, ok := st.templates[sent.Id]; ok {
				tpl.AllowedRequesters = put.AllowedRequesters
				tpl.UseAllowedRequesters = put.UseAllowedRequesters
			}
			_ = json.NewEncoder(w).Encode(api.UpdateTemplateResponse{GetTemplateResponse: api.GetTemplateResponse{Id: sent.Id}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return st, srv
}

func roleBindingResource(srv *httptest.Server) resourceCertificateTemplateRoleBinding {
	return resourceCertificateTemplateRoleBinding{p: provider{configured: true, client: newTemplateTestClient(srv)}}
}

func roleBindingSchema(t *testing.T) tfsdk.Schema {
	t.Helper()
	schema, d := resourceCertificateTemplateRoleBindingType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	return schema
}

// Destroy only detaches. A template whose list names the role but which has enforcement off is
// updated once: the role is removed and UseAllowedRequesters stays false. (Before: Destroy first
// "re-attached" the role, which switched enforcement on, and then removed it, which left enforcement
// on for the remaining entries: two PUTs and a changed UseAllowedRequesters.)
func TestUnitRoleBindingDelete_ListedButNotEnforcedSendsOneRemovalAndKeepsEnforcementOff(t *testing.T) {
	ctx := context.Background()
	st, srv := newStatefulTemplatesServer(t, api.GetTemplateResponse{
		Id: 4, CommonName: "WebServer", UseAllowedRequesters: false, AllowedRequesters: []string{"Role", "Other"},
	})
	schema := roleBindingSchema(t)
	state := stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Value: "abc"}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("WebServer"),
	})
	resp := &tfsdk.DeleteResourceResponse{State: state}
	roleBindingResource(srv).Delete(ctx, tfsdk.DeleteResourceRequest{State: state}, resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	require.Len(t, st.puts, 1, "destroy must send exactly one PUT: %+v", st.puts)
	assert.Equal(t, []string{"Other"}, st.puts[0].AllowedRequesters)
	assert.False(t, st.puts[0].UseAllowedRequesters, "removing a role must not switch enforcement on")
	assert.True(t, resp.State.Raw.IsNull(), "the binding is removed from state")
}

// Destroy of a role that is already absent from the template sends no PUT at all.
func TestUnitRoleBindingDelete_RoleNotListedSendsNoPut(t *testing.T) {
	ctx := context.Background()
	st, srv := newStatefulTemplatesServer(t, api.GetTemplateResponse{
		Id: 4, CommonName: "WebServer", UseAllowedRequesters: true, AllowedRequesters: []string{"Other"},
	})
	state := stateWith(t, roleBindingSchema(t), CertificateTemplateRoleBinding{
		ID: types.String{Value: "abc"}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("WebServer"),
	})
	resp := &tfsdk.DeleteResourceResponse{State: state}
	roleBindingResource(srv).Delete(ctx, tfsdk.DeleteResourceRequest{State: state}, resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, st.puts, "nothing to remove, so nothing to PUT")
}

func TestUnitRemoveRoleFromTemplate_PreservesUseAllowedRequesters(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		enforced bool
		listed   []string
		wantList []string
		wantUse  bool
		wantPuts int
	}{
		{"enforcement off stays off", false, []string{"Role", "Other"}, []string{"Other"}, false, 1},
		{"enforcement on stays on while others remain", true, []string{"Role", "Other"}, []string{"Other"}, true, 1},
		{"emptied list turns enforcement off", true, []string{"Role"}, nil, false, 1},
		{"emptied list with enforcement already off", false, []string{"Role"}, nil, false, 1},
		{"role not listed: no PUT", true, []string{"Other"}, nil, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, srv := newStatefulTemplatesServer(t, api.GetTemplateResponse{
				Id: 4, CommonName: "WebServer", UseAllowedRequesters: tc.enforced, AllowedRequesters: tc.listed,
			})
			diags := removeRoleFromTemplate(ctx, newTemplateTestClient(srv), "role", 4)
			require.False(t, diags.HasError(), "%v", diags)
			require.Len(t, st.puts, tc.wantPuts)
			if tc.wantPuts == 1 {
				assert.Equal(t, tc.wantList, st.puts[0].AllowedRequesters)
				assert.Equal(t, tc.wantUse, st.puts[0].UseAllowedRequesters)
			}
		})
	}
}

// Update attaches only the added template and detaches only the dropped one. The template that stays
// in the binding is not touched even though its admin left enforcement off.
func TestUnitRoleBindingUpdate_TouchesOnlyAddedAndRemovedTemplates(t *testing.T) {
	ctx := context.Background()
	st, srv := newStatefulTemplatesServer(t,
		api.GetTemplateResponse{Id: 4, CommonName: "A", UseAllowedRequesters: true, AllowedRequesters: []string{"Role"}},
		api.GetTemplateResponse{Id: 5, CommonName: "B", UseAllowedRequesters: false, AllowedRequesters: []string{"Role"}},
		api.GetTemplateResponse{Id: 6, CommonName: "C", UseAllowedRequesters: true, AllowedRequesters: []string{"Other"}},
	)
	schema := roleBindingSchema(t)
	state := stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Value: "abc"}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A", "B"),
	})
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Value: "abc"}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("B", "C"),
	}).Raw}
	resp := &tfsdk.UpdateResourceResponse{State: state}
	roleBindingResource(srv).Update(ctx, tfsdk.UpdateResourceRequest{State: state, Plan: plan}, resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.ElementsMatch(t, []int{4, 6}, st.putIDs(), "only A (removed) and C (added) may be updated; B stays untouched: %+v", st.puts)
	b := st.snapshot(5)
	assert.False(t, b.UseAllowedRequesters, "B's admin-chosen enforcement setting must be left alone")
	c := st.snapshot(6)
	assert.True(t, c.UseAllowedRequesters)
	assert.Equal(t, []string{"Other", "Role"}, c.AllowedRequesters)
	a := st.snapshot(4)
	assert.Empty(t, a.AllowedRequesters)
	assert.False(t, a.UseAllowedRequesters, "emptied list: enforcement off")
}

// Update with an unchanged template set sends nothing, even if a listed template has enforcement off.
func TestUnitRoleBindingUpdate_UnchangedTemplatesSendNoPut(t *testing.T) {
	ctx := context.Background()
	st, srv := newStatefulTemplatesServer(t,
		api.GetTemplateResponse{Id: 5, CommonName: "B", UseAllowedRequesters: false, AllowedRequesters: []string{"Role"}},
	)
	schema := roleBindingSchema(t)
	obj := CertificateTemplateRoleBinding{ID: types.String{Value: "abc"}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("B")}
	state := stateWith(t, schema, obj)
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, obj).Raw}
	resp := &tfsdk.UpdateResourceResponse{State: state}
	roleBindingResource(srv).Update(ctx, tfsdk.UpdateResourceRequest{State: state, Plan: plan}, resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, st.puts)
}

// Create is the explicit attach: a role listed on a template with enforcement off gets exactly one PUT
// that turns enforcement on and keeps the list; an unlisted role is appended.
func TestUnitRoleBindingCreate_AttachesPlanSetOnly(t *testing.T) {
	ctx := context.Background()
	st, srv := newStatefulTemplatesServer(t,
		api.GetTemplateResponse{Id: 4, CommonName: "A", UseAllowedRequesters: false, AllowedRequesters: []string{"Role", "Other"}},
		api.GetTemplateResponse{Id: 5, CommonName: "B", UseAllowedRequesters: true, AllowedRequesters: []string{"Other"}},
		api.GetTemplateResponse{Id: 6, CommonName: "Unrelated", UseAllowedRequesters: false, AllowedRequesters: []string{"Role"}},
	)
	schema := roleBindingSchema(t)
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Unknown: true}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A", "B", "a"),
	}).Raw}
	resp := &tfsdk.CreateResourceResponse{State: emptyState(ctx, schema)}
	roleBindingResource(srv).Create(ctx, tfsdk.CreateResourceRequest{Plan: plan}, resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Equal(t, []int{4, 5}, st.putIDs(), "one PUT per distinct template in the plan, none for others: %+v", st.puts)
	assert.True(t, st.snapshot(4).UseAllowedRequesters)
	assert.Equal(t, []string{"Role", "Other"}, st.snapshot(4).AllowedRequesters)
	assert.Equal(t, []string{"Other", "Role"}, st.snapshot(5).AllowedRequesters)
	assert.False(t, st.snapshot(6).UseAllowedRequesters, "templates outside the plan are never touched")
}

// ---- D: one id format everywhere. ----

func TestUnitTemplateRoleBindingID_IsTheHashedFormat(t *testing.T) {
	want := fmt.Sprintf("%x", sha256.Sum256([]byte("Role-A-B")))
	assert.Equal(t, want, templateRoleBindingID("Role", []string{"A", "B"}).Value)
	assert.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte("Role-"))), templateRoleBindingID("Role", nil).Value)
}

func TestUnitRoleBindingCreateAndImportAgreeOnID(t *testing.T) {
	ctx := context.Background()
	_, srv := newStatefulTemplatesServer(t,
		api.GetTemplateResponse{Id: 4, CommonName: "A", UseAllowedRequesters: true, AllowedRequesters: []string{"Role"}},
	)
	schema := roleBindingSchema(t)
	res := roleBindingResource(srv)

	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Unknown: true}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A"),
	}).Raw}
	created := &tfsdk.CreateResourceResponse{State: emptyState(ctx, schema)}
	res.Create(ctx, tfsdk.CreateResourceRequest{Plan: plan}, created)
	require.False(t, created.Diagnostics.HasError(), "%v", created.Diagnostics)
	var cGot CertificateTemplateRoleBinding
	require.False(t, created.State.Get(ctx, &cGot).HasError())

	imported := &tfsdk.ImportResourceStateResponse{State: emptyState(ctx, schema)}
	res.ImportState(ctx, tfsdk.ImportResourceStateRequest{ID: "Role"}, imported)
	require.False(t, imported.Diagnostics.HasError(), "%v", imported.Diagnostics)
	var iGot CertificateTemplateRoleBinding
	require.False(t, imported.State.Get(ctx, &iGot).HasError())

	assert.Equal(t, cGot.ID.Value, iGot.ID.Value)
	assert.Equal(t, templateRoleBindingID("Role", []string{"A"}).Value, cGot.ID.Value)
}

// Update recomputes the id from the planned role and templates, so it matches what Create/Import
// would produce for the new configuration. (Before: Update kept the id from state.)
func TestUnitRoleBindingUpdate_RecomputesID(t *testing.T) {
	ctx := context.Background()
	_, srv := newStatefulTemplatesServer(t,
		api.GetTemplateResponse{Id: 4, CommonName: "A", UseAllowedRequesters: true, AllowedRequesters: []string{"Role"}},
		api.GetTemplateResponse{Id: 5, CommonName: "B", UseAllowedRequesters: true, AllowedRequesters: []string{"Other"}},
	)
	schema := roleBindingSchema(t)
	oldID := templateRoleBindingID("Role", []string{"A"})
	state := stateWith(t, schema, CertificateTemplateRoleBinding{ID: oldID, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A")})
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Unknown: true}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A", "B"),
	}).Raw}
	resp := &tfsdk.UpdateResourceResponse{State: state}
	roleBindingResource(srv).Update(ctx, tfsdk.UpdateResourceRequest{State: state, Plan: plan}, resp)

	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	var got CertificateTemplateRoleBinding
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.Equal(t, templateRoleBindingID("Role", []string{"A", "B"}).Value, got.ID.Value)
	assert.NotEqual(t, oldID.Value, got.ID.Value)
}

// Read keeps a stored id (whatever format an older provider version wrote) and only fills in an empty one.
func TestUnitRoleBindingRead_KeepsStoredIDAndFillsEmptyOne(t *testing.T) {
	ctx := context.Background()
	_, srv := newStatefulTemplatesServer(t, api.GetTemplateResponse{Id: 4, CommonName: "A"})
	schema := roleBindingSchema(t)
	read := func(id types.String) CertificateTemplateRoleBinding {
		st := stateWith(t, schema, CertificateTemplateRoleBinding{ID: id, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A")})
		resp := &tfsdk.ReadResourceResponse{State: st}
		roleBindingResource(srv).Read(ctx, tfsdk.ReadResourceRequest{State: st}, resp)
		require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
		var got CertificateTemplateRoleBinding
		require.False(t, resp.State.Get(ctx, &got).HasError())
		return got
	}
	assert.Equal(t, "Role[A]", read(types.String{Value: "Role[A]"}).ID.Value, "an existing id is never rewritten on refresh")
	assert.Equal(t, templateRoleBindingID("Role", []string{"A"}).Value, read(types.String{Value: ""}).ID.Value)
}

// ---- #7: the message for a template that no longer exists says what to do. ----

func TestUnitVerifyTemplateNames_MissingPlanTemplateMessageNamesTheAttribute(t *testing.T) {
	templates := []api.GetTemplateResponse{{Id: 1, CommonName: "WebServer"}}
	_, diags := verifyTemplateNames(context.Background(), templates, []string{"Gone"}, templateNameSidePlan)
	require.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityError))
	detail := diag.Diagnostics(diags).Errors()[0].Detail()
	assert.Contains(t, detail, "'Gone'")
	assert.Contains(t, detail, "does not exist in Keyfactor Command")
	assert.Contains(t, detail, "Remove it from template_short_names")
}

func TestUnitRoleBindingUpdate_TemplateGoneFromCommandSaysToRemoveIt(t *testing.T) {
	ctx := context.Background()
	st, srv := newStatefulTemplatesServer(t, api.GetTemplateResponse{Id: 4, CommonName: "A"})
	schema := roleBindingSchema(t)
	state := stateWith(t, schema, CertificateTemplateRoleBinding{ID: types.String{Value: "x"}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A")})
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, CertificateTemplateRoleBinding{
		ID: types.String{Unknown: true}, RoleName: types.String{Value: "Role"}, TemplateNames: stringList("A", "Deleted"),
	}).Raw}
	resp := &tfsdk.UpdateResourceResponse{State: state}
	roleBindingResource(srv).Update(ctx, tfsdk.UpdateResourceRequest{State: state, Plan: plan}, resp)

	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "template_short_names")
	assert.Empty(t, st.puts, "nothing may be changed when the plan names a missing template")
}

// ---- #8: a template short name is resolved to its real id, not to its position in the list. ----

func TestUnitAddAllowedRequester_ByShortNameUsesTheTemplateID(t *testing.T) {
	st, srv := newStatefulTemplatesServer(t,
		api.GetTemplateResponse{Id: 10, CommonName: "First"},
		api.GetTemplateResponse{Id: 11, CommonName: "WebServer", UseAllowedRequesters: true, AllowedRequesters: []string{"Other"}},
	)
	diags := addAllowedRequesterToTemplate(context.Background(), newTemplateTestClient(srv), "Role", "webserver")
	require.False(t, diags.HasError(), "%v", diags)
	require.Len(t, st.puts, 1)
	assert.Equal(t, 11, st.puts[0].ID)
	assert.Equal(t, []string{"Other", "Role"}, st.puts[0].AllowedRequesters)

	// An unknown short name is a clear error and changes nothing.
	diags = addAllowedRequesterToTemplate(context.Background(), newTemplateTestClient(srv), "Role", "Nope")
	require.True(t, diags.HasError())
	assert.Len(t, diags.Errors(), 1, "%v", diags)
	assert.Len(t, st.puts, 1)
}

func TestUnitRoleBindingMarkdownDescriptionUsesBackticks(t *testing.T) {
	md := roleBindingSchema(t).MarkdownDescription
	assert.Contains(t, md, "`/Templates`")
	assert.NotContains(t, md, `"/Templates"`)
}
