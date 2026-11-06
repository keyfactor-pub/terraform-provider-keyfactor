package keyfactor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// PR #219 review finding #4: Update() PUTs a stale role list.
//
// PUT /EnrollmentPatterns/{id} replaces the whole role list. The plan's
// associated_role_names is the refresh-time snapshot, so when it is undeclared,
// unchanged, or pinned by lifecycle { ignore_changes } (Terraform Core
// substitutes prior state into the plan), sending it verbatim silently undoes
// keyfactor_enrollment_pattern_role_binding changes made after the refresh.
// Only an explicitly declared, CHANGED value is authoritative; otherwise
// Update() must send the roles from its fresh pre-PUT GET.
// ---------------------------------------------------------------------------

func roleSet(names ...string) types.Set {
	elems := make([]attr.Value, 0, len(names))
	for _, n := range names {
		elems = append(elems, types.String{Value: n})
	}
	return types.Set{ElemType: types.StringType, Elems: elems}
}

func TestUnitEnrollmentPatternRoleNamesAuthoritative(t *testing.T) {
	t.Parallel()
	nullSet := types.Set{Null: true, ElemType: types.StringType}
	unknownSet := types.Set{Unknown: true, ElemType: types.StringType}

	cases := []struct {
		name                string
		config, plan, state types.Set
		want                bool
	}{
		{"undeclared (config null), plan carries state", nullSet, roleSet("a", "b"), roleSet("a", "b"), false},
		{"undeclared, state null", nullSet, nullSet, nullSet, false},
		{"declared, unchanged", roleSet("a", "b"), roleSet("a", "b"), roleSet("a", "b"), false},
		{"declared + ignore_changes (plan pinned to state, config differs)", roleSet("a"), roleSet("a", "b"), roleSet("a", "b"), false},
		{"declared and changed", roleSet("a"), roleSet("a"), roleSet("a", "b"), true},
		{"declared, state was null, now set", roleSet("a"), roleSet("a"), nullSet, true},
		{"declared empty, state non-empty (explicit clear)", roleSet(), roleSet(), roleSet("a"), true},
		{"declared but unknown at plan time", unknownSet, unknownSet, roleSet("a"), true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := enrollmentPatternRoleNamesAuthoritative(c.config, c.plan, c.state); got != c.want {
				t.Fatalf("enrollmentPatternRoleNamesAuthoritative = %v, want %v", got, c.want)
			}
		})
	}
}

// newEnrollmentPatternRolesUpdateServer serves getJSON for GET and records the
// PUT body, echoing the PUT's own AssociatedRoles back (like Command does) so
// the response reflects what was actually sent.
func newEnrollmentPatternRolesUpdateServer(t *testing.T, getJSON string, putBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(getJSON))
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading PUT body: %v", err)
			}
			*putBody = body
			var req struct {
				AssociatedRoles []string `json:"AssociatedRoles"`
			}
			_ = json.Unmarshal(body, &req)
			roles := make([]map[string]interface{}, 0, len(req.AssociatedRoles))
			for i, n := range req.AssociatedRoles {
				roles = append(roles, map[string]interface{}{"Id": i + 1, "Name": n})
			}
			out, _ := json.Marshal(map[string]interface{}{"Id": 42, "Name": "Demo Pattern_TF", "AssociatedRoles": roles})
			_, _ = w.Write(out)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
}

func sentRoleNames(t *testing.T, putBody []byte) []string {
	t.Helper()
	if len(putBody) == 0 {
		t.Fatal("Update() made no PUT request")
	}
	var m struct {
		AssociatedRoles []string `json:"AssociatedRoles"`
	}
	if err := json.Unmarshal(putBody, &m); err != nil {
		t.Fatalf("PUT body not JSON: %v (%s)", err, putBody)
	}
	sort.Strings(m.AssociatedRoles)
	return m.AssociatedRoles
}

func sortedSetStrings(s types.Set) []string {
	out := make([]string, 0, len(s.Elems))
	for _, e := range s.Elems {
		out = append(out, e.(types.String).Value)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// runPatternRolesUpdate drives resourceEnrollmentPattern.Update with the given
// config/plan/state role sets against a server whose CURRENT roles are
// serverRoles, and returns the PUT's role list and the resulting state.
func runPatternRolesUpdate(t *testing.T, config, plan, prior types.Set, serverRoles []string) ([]string, KeyfactorEnrollmentPatternState) {
	t.Helper()
	ctx := context.Background()

	roleObjs := make([]map[string]interface{}, 0, len(serverRoles))
	for i, n := range serverRoles {
		roleObjs = append(roleObjs, map[string]interface{}{"Id": i + 1, "Name": n})
	}
	getJSON, _ := json.Marshal(map[string]interface{}{"Id": 42, "Name": "Demo Pattern_TF", "AssociatedRoles": roleObjs})

	var putBody []byte
	server := newEnrollmentPatternRolesUpdateServer(t, string(getJSON), &putBody)
	defer server.Close()

	schema := enrollmentPatternSchemaForTest(t, ctx)

	mk := func(roles types.Set, withID bool) tfsdk.Plan {
		s := blankEnrollmentPatternState()
		if withID {
			s.ID = types.Int64{Value: 42}
		}
		s.Name = types.String{Value: "Demo Pattern_TF"}
		s.TemplateId = types.Int64{Value: 6}
		s.UseADPermissions = types.Bool{Value: false}
		s.Description = types.String{Value: "d"}
		s.AssociatedRoleNames = roles
		p := tfsdk.Plan{Schema: schema}
		if d := p.Set(ctx, &s); d.HasError() {
			t.Fatalf("test setup: %+v", d)
		}
		return p
	}
	cfgScratch := mk(config, false)
	planObj := mk(plan, true)
	stateScratch := mk(prior, true)

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(server)}}
	req := tfsdk.UpdateResourceRequest{
		Config: tfsdk.Config{Schema: schema, Raw: cfgScratch.Raw},
		Plan:   planObj,
		State:  tfsdk.State{Schema: schema, Raw: stateScratch.Raw},
	}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}
	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update diagnostics: %+v", resp.Diagnostics)
	}
	var got KeyfactorEnrollmentPatternState
	if d := resp.State.Get(ctx, &got); d.HasError() {
		t.Fatalf("reading resulting state: %+v", d)
	}
	return sentRoleNames(t, putBody), got
}

// The #4 scenario: pattern + ignore_changes + two bindings; one binding is
// destroyed in the same apply, so the server already lacks "b" when Update()
// runs, while the plan (pinned to refresh-time state by ignore_changes) still
// lists it. The PUT must NOT resurrect "b".
func TestUnitEnrollmentPatternUpdateIgnoreChangesDoesNotResurrectRemovedRole(t *testing.T) {
	t.Parallel()
	declared := roleSet("a")
	refreshTime := roleSet("a", "b") // Core pins plan to prior state under ignore_changes
	sent, state := runPatternRolesUpdate(t, declared, refreshTime, refreshTime, []string{"a"})

	if !equalStrings(sent, []string{"a"}) {
		t.Fatalf("PUT roles = %v, want [a] (the stale refresh-time role b was resurrected)", sent)
	}
	// Core requires post-apply == plan for a known planned value.
	if got := sortedSetStrings(state.AssociatedRoleNames); !equalStrings(got, []string{"a", "b"}) {
		t.Fatalf("state associated_role_names = %v, want the planned [a b] (Core's planned==applied check); next refresh reconciles", got)
	}
}

// The mirror: a binding ADDED after refresh must not be dropped.
func TestUnitEnrollmentPatternUpdateUndeclaredKeepsRoleAddedAfterRefresh(t *testing.T) {
	t.Parallel()
	null := types.Set{Null: true, ElemType: types.StringType}
	refreshTime := roleSet("a")
	sent, _ := runPatternRolesUpdate(t, null, refreshTime, refreshTime, []string{"a", "c"})
	if !equalStrings(sent, []string{"a", "c"}) {
		t.Fatalf("PUT roles = %v, want [a c] (role c added after refresh was dropped)", sent)
	}
}

// An explicitly declared, changed value stays authoritative even though the
// server currently holds something else.
func TestUnitEnrollmentPatternUpdateDeclaredChangeIsAuthoritative(t *testing.T) {
	t.Parallel()
	want := roleSet("x", "y")
	sent, state := runPatternRolesUpdate(t, want, want, roleSet("a"), []string{"a", "c"})
	if !equalStrings(sent, []string{"x", "y"}) {
		t.Fatalf("PUT roles = %v, want [x y]", sent)
	}
	if got := sortedSetStrings(state.AssociatedRoleNames); !equalStrings(got, []string{"x", "y"}) {
		t.Fatalf("state associated_role_names = %v, want [x y]", got)
	}
}
