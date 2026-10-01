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
// Regression tests -- self-healing drift detection for certificate_authority_ids
// (v2.10 design change):
//
// An earlier version of this resource pinned certificate_authority_ids to
// whatever Terraform last wrote to state on every Read(), regardless of what
// the server actually reported (see git history around commit 1c40ee0). That
// meant a CA restriction added/removed directly in Command -- e.g. via the
// Command UI, entirely outside Terraform -- was invisible to `terraform plan`:
// the next refresh would silently re-report the stale, last-applied membership
// instead of the server's real, current one.
//
// enrollmentPatternResponseToState now derives certificate_authority_ids
// directly from the CertificateAuthorities expansion every Create/Read/Update/
// Import response already carries (see its doc comment and
// KeyfactorEnrollmentPatternState's doc comment), and the schema models it
// as a Terraform Set (not a List) specifically so this derivation is safe
// regardless of whatever order Command's expansion happens to return --
// types.Set.Equal() compares membership only, so a Set rebuilt from the
// server's response can never produce a spurious "changed" diff purely from
// reordering, only from an actual membership change. These tests exercise
// Read() directly against a local httptest mock server.
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

// TestUnitEnrollmentPatternReadSurfacesCertificateAuthorityIdsDrift is the
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
// modeling's actual payoff for certificate_authority_ids: even though this
// test's mocked GET response returns CertificateAuthorities in the OPPOSITE
// order from prior state's Elems, the two are the SAME membership -- Read()
// must not need any special-case handling to avoid treating that reordering
// as a change, because types.Set's own Equal() (used by Terraform Core's
// plan diffing, but the reason a List was never safe here) is
// membership-based, not order-based.
func TestUnitEnrollmentPatternReadDoesNotFlagPureReorderAsDrift(t *testing.T) {
	ctx := context.Background()

	// Prior state restricts CAs to ids 1, 2 (in that order); the mocked GET
	// response below echoes the identical two CAs back in the OPPOSITE order
	// (2, 1) -- simulating Command's expansion not preserving submission
	// order, not an actual membership change.
	server := newEnrollmentPatternDriftTestServer(
		t, `{"Id": 42, "Name": "Demo Pattern_TF", "CertificateAuthorities": `+
			`[{"Id": 2, "LogicalName": "CA2"}, {"Id": 1, "LogicalName": "CA1"}]}`,
	)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	state.CertificateAuthorityIds = types.Set{
		ElemType: types.Int64Type,
		Elems: []attr.Value{
			types.Int64{Value: 1},
			types.Int64{Value: 2},
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

	if !finalState.CertificateAuthorityIds.Equal(state.CertificateAuthorityIds) {
		t.Errorf(
			"final state certificate_authority_ids = %+v is not Set-equal to prior state %+v -- a pure reordering "+
				"of the same membership must never look like a change",
			finalState.CertificateAuthorityIds, state.CertificateAuthorityIds,
		)
	}
}
