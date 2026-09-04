package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- self-healing drift detection for associated_role_names
// / certificate_authority_ids (v2.10 design change):
//
// An earlier version of this resource pinned these two attributes to
// whatever Terraform last wrote to state on every Read(), regardless of what
// the server actually reported (see git history around commit 1c40ee0). That
// meant a role or CA restriction added/removed directly in Command -- e.g.
// via the Command UI, entirely outside Terraform -- was invisible to
// `terraform plan`: the next refresh would silently re-report the stale,
// last-applied membership instead of the server's real, current one.
//
// enrollmentPatternResponseToState now derives both attributes directly from
// the same AssociatedRoles/CertificateAuthorities expansion every Create/
// Read/Update/Import response already carries (see its doc comment and
// KeyfactorEnrollmentPatternState's doc comment), and the schema models them
// as Terraform Sets (not Lists) specifically so this derivation is safe
// regardless of whatever order Command's expansion happens to return --
// types.Set.Equal() compares membership only, so a Set rebuilt from the
// server's response can never produce a spurious "changed" diff purely from
// reordering, only from an actual membership change. These tests exercise
// Read() directly against a local httptest mock server (matching the
// established pattern used throughout this package -- see e.g.
// newEnrollmentPatternUpdateTestServer/newEnrollmentPatternImportTestServer
// -- rather than a recorded VCR cassette, since this is resource CRUD logic
// exercised the same way every other TestUnit* test in this file already
// exercises Create/Read/Update/ImportState) to prove the new behavior:
// membership changed out-of-band between the last apply and this refresh is
// now surfaced in the refreshed state, not silently masked.
// ---------------------------------------------------------------------------

// newEnrollmentPatternDriftTestServer serves a canned GetById response whose
// AssociatedRoles/CertificateAuthorities are handed in by the caller, so
// each test/sub-case can simulate a different "current server membership"
// independent of whatever the prior Terraform state says.
func newEnrollmentPatternDriftTestServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

// TestUnitEnrollmentPatternReadSurfacesAssociatedRoleNamesDrift is the direct
// regression test: prior Terraform state has associated_role_names =
// ["RoleA"] (as if the last apply set it), but the mocked GetById response
// -- simulating a role reassignment made directly in Command since that
// apply -- now reports AssociatedRoles = [{"RoleB"}]. Read() must surface
// "RoleB" in the refreshed state, not "RoleA".
func TestUnitEnrollmentPatternReadSurfacesAssociatedRoleNamesDrift(t *testing.T) {
	ctx := context.Background()

	server := newEnrollmentPatternDriftTestServer(
		t, `{"Id": 42, "Name": "Demo Pattern_TF", "AssociatedRoles": [{"Id": 2, "Name": "RoleB"}]}`,
	)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	// Prior state: what the last Terraform apply actually wrote. Note this
	// is deliberately DIFFERENT from what the mocked GET now returns, which
	// is exactly the out-of-band drift scenario under test.
	state.AssociatedRoleNames = types.Set{
		ElemType: types.StringType,
		Elems:    []attr.Value{types.String{Value: "RoleA"}},
	}
	state.Policies = &EnrollmentPatternResourcePolicy{}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned diagnostics: %+v", resp.Diagnostics)
	}

	var finalState KeyfactorEnrollmentPatternState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}

	var got []string
	finalState.AssociatedRoleNames.ElementsAs(ctx, &got, false)
	if len(got) != 1 || got[0] != "RoleB" {
		t.Errorf(
			"final state associated_role_names = %v, want [RoleB] (derived from the fresh GET response, "+
				"reflecting the out-of-band membership change) -- got the stale prior state value instead if "+
				"this still reads [RoleA]",
			got,
		)
	}
}

// TestUnitEnrollmentPatternReadSurfacesCertificateAuthorityIdsDrift is the
// certificate_authority_ids counterpart to the associated_role_names test
// above.
func TestUnitEnrollmentPatternReadSurfacesCertificateAuthorityIdsDrift(t *testing.T) {
	ctx := context.Background()

	server := newEnrollmentPatternDriftTestServer(
		t, `{"Id": 42, "Name": "Demo Pattern_TF", "CertificateAuthorities": [{"Id": 99, "LogicalName": "NewCA"}]}`,
	)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	// Prior state restricted CAs to id 1; the fresh GET below reports the
	// pattern is now restricted to id 99 instead -- an out-of-band change.
	state.CertificateAuthorityIds = types.Set{
		ElemType: types.Int64Type,
		Elems:    []attr.Value{types.Int64{Value: 1}},
	}
	state.Policies = &EnrollmentPatternResourcePolicy{}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned diagnostics: %+v", resp.Diagnostics)
	}

	var finalState KeyfactorEnrollmentPatternState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}

	var got []int64
	finalState.CertificateAuthorityIds.ElementsAs(ctx, &got, false)
	if len(got) != 1 || got[0] != 99 {
		t.Errorf(
			"final state certificate_authority_ids = %v, want [99] (derived from the fresh GET response, "+
				"reflecting the out-of-band CA restriction change) -- got the stale prior state value instead if "+
				"this still reads [1]",
			got,
		)
	}
}

// TestUnitEnrollmentPatternReadDoesNotFlagPureReorderAsDrift proves the Set
// modeling's actual payoff: even though this test's mocked GET response
// returns AssociatedRoles in the OPPOSITE order from prior state's Elems,
// the two are the SAME membership -- Read() must not need any special-case
// handling to avoid treating that reordering as a change, because
// types.Set's own Equal() (used by Terraform Core's plan diffing, not
// exercised directly by this unit test, but the reason a List was never
// safe here) is membership-based, not order-based. This test asserts the
// practical, testable half of that: ElementsAs on the refreshed value
// contains exactly the same two names, regardless of the order the mocked
// response happened to list them in.
func TestUnitEnrollmentPatternReadDoesNotFlagPureReorderAsDrift(t *testing.T) {
	ctx := context.Background()

	// Prior state lists RoleA, RoleB (in that order); the mocked GET
	// response below echoes the identical two roles back in the OPPOSITE
	// order (RoleB, RoleA) -- simulating Command's expansion not preserving
	// submission order, not an actual membership change.
	server := newEnrollmentPatternDriftTestServer(
		t, `{"Id": 42, "Name": "Demo Pattern_TF", "AssociatedRoles": `+
			`[{"Id": 2, "Name": "RoleB"}, {"Id": 1, "Name": "RoleA"}]}`,
	)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	state.AssociatedRoleNames = types.Set{
		ElemType: types.StringType,
		Elems: []attr.Value{
			types.String{Value: "RoleA"},
			types.String{Value: "RoleB"},
		},
	}
	state.Policies = &EnrollmentPatternResourcePolicy{}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.ReadResourceRequest{State: stateObj}
	resp := &tfsdk.ReadResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned diagnostics: %+v", resp.Diagnostics)
	}

	var finalState KeyfactorEnrollmentPatternState
	if d := resp.State.Get(ctx, &finalState); d.HasError() {
		t.Fatalf("failed to read final state: %+v", d)
	}

	if !finalState.AssociatedRoleNames.Equal(state.AssociatedRoleNames) {
		t.Errorf(
			"final state associated_role_names = %+v is not Set-equal to prior state %+v -- a pure reordering "+
				"of the same membership must never look like a change",
			finalState.AssociatedRoleNames, state.AssociatedRoleNames,
		)
	}
}
