package keyfactor

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflogtest"
)

// ---------------------------------------------------------------------------
// Regression tests -- PR #210 full-review round 6 finding FIX-Q:
//
// enrollmentPatternPolicyRelevantFieldChanges logs an "attempted"
// policies.default_certificate_owner_role_id change line BEFORE the
// Update() PUT call runs, so that field always has audit signal even when
// the PUT subsequently fails. Its sibling,
// policies.default_certificate_owner_role_name, is audited by a separate
// function (enrollmentPatternOwnerRoleNameChange) that only runs AFTER a
// successful PUT response -- so on a PUT failure, the id field logs its
// attempt but the name field logs nothing at all, leaving an auditor with
// no human-readable context for a failed ownership-role change (and no way
// to recover it later if the role is renamed/deleted).
//
// enrollmentPatternOwnerRoleNameChangeAttemptedOnFailure closes this gap
// with a best-effort substitute logged from Update()'s PUT-error branch.
// ---------------------------------------------------------------------------

func TestUnitEnrollmentPatternOwnerRoleNameChangeAttemptedOnFailure(t *testing.T) {
	t.Parallel()

	t.Run("reports a best-effort attempt when the owner role id was changing", func(t *testing.T) {
		t.Parallel()
		prior := &EnrollmentPatternResourcePolicy{
			DefaultCertificateOwnerRoleId:   types.Int64{Value: 5},
			DefaultCertificateOwnerRoleName: types.String{Value: "Role A"},
		}
		planned := &EnrollmentPatternResourcePolicy{
			DefaultCertificateOwnerRoleId: types.Int64{Value: 42},
			// The new name is never known pre-PUT -- that's the whole
			// reason this field can't be resolved on a failure.
		}

		got := enrollmentPatternOwnerRoleNameChangeAttemptedOnFailure(prior, planned)
		want := `policies.default_certificate_owner_role_name: "Role A" -> (update failed, new value unresolved)`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("no id change in flight reports empty string", func(t *testing.T) {
		t.Parallel()
		prior := &EnrollmentPatternResourcePolicy{
			DefaultCertificateOwnerRoleId:   types.Int64{Value: 5},
			DefaultCertificateOwnerRoleName: types.String{Value: "Role A"},
		}
		planned := &EnrollmentPatternResourcePolicy{
			DefaultCertificateOwnerRoleId: types.Int64{Value: 5},
		}

		if got := enrollmentPatternOwnerRoleNameChangeAttemptedOnFailure(prior, planned); got != "" {
			t.Errorf("got %q, want empty string when the owner role id is not changing", got)
		}
	})

	t.Run("nil prior/planned render as (null), not a zero value", func(t *testing.T) {
		t.Parallel()
		planned := &EnrollmentPatternResourcePolicy{DefaultCertificateOwnerRoleId: types.Int64{Value: 42}}

		got := enrollmentPatternOwnerRoleNameChangeAttemptedOnFailure(nil, planned)
		want := `policies.default_certificate_owner_role_name: (null) -> (update failed, new value unresolved)`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// newEnrollmentPatternFailingUpdateTestServer answers the pre-update GET
// /EnrollmentPatterns/{id} with a canned response whose default certificate
// owner role differs from what the update is about to request, then fails
// the subsequent PUT /EnrollmentPatterns/{id} outright -- reproducing the
// exact scenario FIX-Q addresses: an in-flight owner-role-id change whose
// PUT never succeeds.
func newEnrollmentPatternFailingUpdateTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(
				`{"Id": 42, "Name": "Demo Pattern_TF", "Policies": ` +
					`{"DefaultCertificateOwnerRoleId": 5, "DefaultCertificateOwnerRoleName": "Role A"}}`,
			))
		case http.MethodPut:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"Message": "simulated PUT failure"}`))
		default:
			t.Fatalf("unexpected request method %s %s", r.Method, r.URL.Path)
		}
	}))
}

// TestUnitEnrollmentPatternUpdateLogsOwnerRoleNameAttemptOnFailedPUT is the
// end-to-end regression test for FIX-Q: with a real (simulated) PUT
// failure, and an owner-role-id change in flight, Update() must still emit
// a role-name-related audit log line -- previously nothing would have been
// logged for this field on this path at all.
func TestUnitEnrollmentPatternUpdateLogsOwnerRoleNameAttemptOnFailedPUT(t *testing.T) {
	var buf bytes.Buffer
	ctx := tflogtest.RootLogger(context.Background(), &buf)

	server := newEnrollmentPatternFailingUpdateTestServer(t)
	defer server.Close()

	sdkClient := newTemplateUpdateSDKClient(server)
	schema := enrollmentPatternSchemaForTest(t, ctx)

	state := blankEnrollmentPatternState()
	state.ID = types.Int64{Value: 42}
	state.Name = types.String{Value: "Demo Pattern_TF"}
	state.TemplateId = types.Int64{Value: 6}
	// blankEnrollmentPatternState's AssociatedRoleNames placeholder uses an
	// Int64 ElemType -- every other test in this package overwrites it with
	// the real String ElemType before calling state.Set (see e.g.
	// resource_keyfactor_enrollment_pattern_update_unit_test.go).
	state.AssociatedRoleNames = types.List{Null: true, ElemType: types.StringType}
	state.Policies = &EnrollmentPatternResourcePolicy{
		DefaultCertificateOwnerRoleId:   types.Int64{Value: 5},
		DefaultCertificateOwnerRoleName: types.String{Value: "Role A"},
	}

	// Config: the user is changing the owner role id from 5 to 42. The PUT
	// this triggers will fail (see newEnrollmentPatternFailingUpdateTestServer),
	// so the genuinely-resolved new name (whatever role 42 actually is) is
	// never learned.
	config := state
	config.Policies = &EnrollmentPatternResourcePolicy{
		DefaultCertificateOwnerRoleId: types.Int64{Value: 42},
	}

	stateObj := tfsdk.State{Schema: schema}
	if d := stateObj.Set(ctx, &state); d.HasError() {
		t.Fatalf("test setup: state.Set returned diagnostics: %+v", d)
	}
	configScratch := tfsdk.Plan{Schema: schema}
	if d := configScratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("test setup: config.Set returned diagnostics: %+v", d)
	}
	configObj := tfsdk.Config{Schema: schema, Raw: configScratch.Raw}
	planObj := tfsdk.Plan{Schema: schema, Raw: configScratch.Raw}

	r := resourceEnrollmentPattern{p: provider{configured: true, sdkClient: sdkClient}}
	req := tfsdk.UpdateResourceRequest{Plan: planObj, State: stateObj, Config: configObj}
	resp := &tfsdk.UpdateResourceResponse{State: tfsdk.State{Schema: schema}}

	r.Update(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("Update should have returned a diagnostics error for the simulated PUT failure, got none")
	}

	messages := strings.Join(decodedLogMessages(t, buf.String()), "\n")
	if !strings.Contains(messages, "policies.default_certificate_owner_role_name") {
		t.Errorf(
			"expected a policies.default_certificate_owner_role_name audit log line on the failed-PUT path "+
				"(previously nothing was logged for this field at all when the PUT failed), got log output: %s",
			messages,
		)
	}
	if !strings.Contains(messages, "Role A") {
		t.Errorf("expected the failed-PUT audit log line to include the prior role name %q for context, got: %s", "Role A", messages)
	}
}
