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
