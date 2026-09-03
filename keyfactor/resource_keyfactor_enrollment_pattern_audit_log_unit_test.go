package keyfactor

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression test -- PR #210 full-review round 2 finding F5:
//
// resourceEnrollmentPattern.Update logged only "Updating enrollment pattern
// ID %d" -- no old/new values for the policy-relevant fields actually
// changing (who can enroll, how strictly, who owns the resulting
// certificates), leaving an incomplete audit trail for a compliance review.
// enrollmentPatternPolicyRelevantFieldChanges is the pure diff-detection
// function factored out of Update() so this can be verified directly,
// without standing up an HTTP mock for the full Update() call.
// ---------------------------------------------------------------------------

func TestUnitEnrollmentPatternPolicyRelevantFieldChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("no changes produces no entries", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames:     types.List{Null: true, ElemType: types.StringType},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			ForceTemplateDefault:    types.Bool{Null: true},
			Policies: &EnrollmentPatternResourcePolicy{
				RFCEnforcement: types.Bool{Value: true},
			},
		}
		plan := state // identical copy

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if len(got) != 0 {
			t.Errorf("got %+v, want no changes for identical state/plan", got)
		}
	})

	t.Run("associated_role_names change is reported", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames: types.List{
				ElemType: types.StringType,
				Elems:    []attr.Value{types.String{Value: "Administrator"}},
			},
		}
		plan := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames: types.List{
				ElemType: types.StringType,
				Elems:    []attr.Value{types.String{Value: "Operator"}},
			},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "associated_role_names") {
			t.Errorf("got %+v, want an entry for associated_role_names", got)
		}
	})

	t.Run("certificate_authority_ids change is reported", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
		}
		plan := KeyfactorEnrollmentPatternState{
			CertificateAuthorityIds: types.List{
				ElemType: types.Int64Type,
				Elems:    []attr.Value{types.Int64{Value: 5}},
			},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "certificate_authority_ids") {
			t.Errorf("got %+v, want an entry for certificate_authority_ids", got)
		}
	})

	t.Run("policies.rfc_enforcement change is reported", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{RFCEnforcement: types.Bool{Value: false}},
		}
		plan := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{RFCEnforcement: types.Bool{Value: true}},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "policies.rfc_enforcement") {
			t.Errorf("got %+v, want an entry for policies.rfc_enforcement", got)
		}
	})

	t.Run("policies.certificate_owner_role and default_certificate_owner_role_id changes are reported", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{
				CertificateOwnerRole:          types.Int64{Value: 0},
				DefaultCertificateOwnerRoleId: types.Int64{Null: true},
			},
		}
		plan := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{
				CertificateOwnerRole:          types.Int64{Value: 2},
				DefaultCertificateOwnerRoleId: types.Int64{Value: 42},
			},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "policies.certificate_owner_role") {
			t.Errorf("got %+v, want an entry for policies.certificate_owner_role", got)
		}
		if !anyContains(got, "policies.default_certificate_owner_role_id") {
			t.Errorf("got %+v, want an entry for policies.default_certificate_owner_role_id", got)
		}
	})

	// ---------------------------------------------------------------------
	// Regression tests -- PR #210 full-review round 2 finding FIX-C:
	// policies.default_certificate_owner_override, policies.primary_key_
	// algorithms, and policies.alternative_key_algorithms were not audited
	// on Update() despite being exactly as security-relevant as the
	// adjacent fields already covered (access-control override, allowed
	// key types/sizes/curves).
	// ---------------------------------------------------------------------

	t.Run("policies.default_certificate_owner_override change is reported", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{DefaultCertificateOwnerOverride: types.Bool{Value: false}},
		}
		plan := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{DefaultCertificateOwnerOverride: types.Bool{Value: true}},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "policies.default_certificate_owner_override") {
			t.Errorf("got %+v, want an entry for policies.default_certificate_owner_override", got)
		}
	})

	t.Run("policies.primary_key_algorithms change is reported", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{
				PrimaryKeyAlgorithms: []EnrollmentPatternResourceAlgorithm{
					{Name: types.String{Value: "RSA"}},
				},
			},
		}
		plan := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{
				PrimaryKeyAlgorithms: []EnrollmentPatternResourceAlgorithm{
					{Name: types.String{Value: "ECDSA"}},
				},
			},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "policies.primary_key_algorithms") {
			t.Errorf("got %+v, want an entry for policies.primary_key_algorithms", got)
		}
	})

	t.Run("policies.alternative_key_algorithms change is reported", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{AlternativeKeyAlgorithms: nil},
		}
		plan := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{
				AlternativeKeyAlgorithms: []EnrollmentPatternResourceAlgorithm{
					{Name: types.String{Value: "Ed25519"}},
				},
			},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "policies.alternative_key_algorithms") {
			t.Errorf("got %+v, want an entry for policies.alternative_key_algorithms", got)
		}
	})

	t.Run("nil Policies on both sides produces no policy entries", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{}
		plan := KeyfactorEnrollmentPatternState{}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if len(got) != 0 {
			t.Errorf("got %+v, want no changes when both Policies are nil", got)
		}
	})

	t.Run("Policies going from nil to non-nil is reported per differing subfield", func(t *testing.T) {
		t.Parallel()
		state := KeyfactorEnrollmentPatternState{}
		plan := KeyfactorEnrollmentPatternState{
			Policies: &EnrollmentPatternResourcePolicy{AllowWildcards: types.Bool{Value: true}},
		}

		got := enrollmentPatternPolicyRelevantFieldChanges(ctx, state, plan)
		if !anyContains(got, "policies.allow_wildcards") {
			t.Errorf("got %+v, want an entry for policies.allow_wildcards", got)
		}
	})
}

func anyContains(entries []string, substr string) bool {
	for _, e := range entries {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// TestUnitTfLogStringHelpers covers the small null/unknown-aware rendering
// helpers (tfBoolLogString/tfInt64LogString/tfStringLogString/
// tfListLogString) that back both resourceEnrollmentPattern.Update's and
// resourceCertificateCollection.Update's audit-log lines (PR #210 full-review
// finding F5) -- these are what actually decide whether two values are
// logged as "changed": e.g. certificate_collection's Update() compares
// tfStringLogString(state.Query) against tfStringLogString(plan.Query)
// before deciding to emit a log line.
func TestUnitTfLogStringHelpers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("tfBoolLogString", func(t *testing.T) {
		t.Parallel()
		if got := tfBoolLogString(types.Bool{Null: true}); got != "(null)" {
			t.Errorf("got %q, want (null)", got)
		}
		if got := tfBoolLogString(types.Bool{Unknown: true}); got != "(unknown)" {
			t.Errorf("got %q, want (unknown)", got)
		}
		if got := tfBoolLogString(types.Bool{Value: true}); got != "true" {
			t.Errorf("got %q, want true", got)
		}
	})

	t.Run("tfInt64LogString", func(t *testing.T) {
		t.Parallel()
		if got := tfInt64LogString(types.Int64{Null: true}); got != "(null)" {
			t.Errorf("got %q, want (null)", got)
		}
		if got := tfInt64LogString(types.Int64{Value: 42}); got != "42" {
			t.Errorf("got %q, want 42", got)
		}
	})

	t.Run("tfStringLogString", func(t *testing.T) {
		t.Parallel()
		if got := tfStringLogString(types.String{Null: true}); got != "(null)" {
			t.Errorf("got %q, want (null)", got)
		}
		// %q-escaped (PR #210 full-review finding FIX-6), not the raw value.
		if got := tfStringLogString(types.String{Value: "CN=Test"}); got != `"CN=Test"` {
			t.Errorf("got %q, want %q", got, `"CN=Test"`)
		}
		// The exact case certificate_collection's Update() relies on: a
		// query changing from one non-null value to another must render as
		// two DIFFERENT strings so the `!=` comparison in Update() decides
		// to log the change.
		old := tfStringLogString(types.String{Value: "CN=Old"})
		newVal := tfStringLogString(types.String{Value: "CN=New"})
		if old == newVal {
			t.Errorf("got equal renderings %q == %q for different query values", old, newVal)
		}
		// CWE-117 regression: an embedded newline must be escaped (rendered
		// as the two characters '\' 'n'), not passed through raw where it
		// could forge a second, visually-separate log line under
		// TF_LOG=DEBUG.
		injected := tfStringLogString(types.String{Value: "Administrator\nlog line forged"})
		if strings.Contains(injected, "\n") {
			t.Errorf("got %q, want no raw newline in rendered log value", injected)
		}
		if !strings.Contains(injected, `\n`) {
			t.Errorf("got %q, want an escaped \\n sequence", injected)
		}
	})

	t.Run("tfListLogString", func(t *testing.T) {
		t.Parallel()
		if got := tfListLogString(ctx, types.List{Null: true, ElemType: types.StringType}); got != "(null)" {
			t.Errorf("got %q, want (null)", got)
		}
		// %q-escaped elements (PR #210 full-review finding FIX-6), not raw
		// values.
		got := tfListLogString(
			ctx, types.List{ElemType: types.StringType, Elems: []attr.Value{types.String{Value: "a"}}},
		)
		if got != `["a"]` {
			t.Errorf("got %q, want %q", got, `["a"]`)
		}
		// CWE-117 regression: an embedded newline in a list element must be
		// escaped, not passed through raw.
		injected := tfListLogString(
			ctx, types.List{ElemType: types.StringType, Elems: []attr.Value{types.String{Value: "a\nb"}}},
		)
		if strings.Contains(injected, "\n") {
			t.Errorf("got %q, want no raw newline in rendered log value", injected)
		}
	})
}

// ---------------------------------------------------------------------------
// Regression test -- PR #210 full-review finding FIX-8:
//
// Create() logged only "Created enrollment pattern ID %d" -- no field-level
// detail for the access-control-relevant fields set on the initial create
// (associated_role_names, certificate_authority_ids, policies.*), unlike
// Update(), which enrollmentPatternPolicyRelevantFieldChanges already
// audits in full. An auditor reconstructing "who was granted enrollment/CA
// access to what, and when" found a bare ID for every creation event and
// full detail for every subsequent update.
// enrollmentPatternCreationAuditFields is the pure function factored out of
// Create() so this can be verified directly.
// ---------------------------------------------------------------------------

func TestUnitEnrollmentPatternCreationAuditFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("reports associated_role_names and certificate_authority_ids", func(t *testing.T) {
		t.Parallel()
		created := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames: types.List{
				ElemType: types.StringType,
				Elems:    []attr.Value{types.String{Value: "InstanceAdmin"}},
			},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
		}
		got := enrollmentPatternCreationAuditFields(ctx, created, types.Bool{Null: true})
		if !anyContains(got, "associated_role_names") {
			t.Errorf("got %+v, want an entry for associated_role_names", got)
		}
		if !anyContains(got, "certificate_authority_ids") {
			t.Errorf("got %+v, want an entry for certificate_authority_ids", got)
		}
	})

	t.Run("reports policy fields when Policies is non-nil", func(t *testing.T) {
		t.Parallel()
		created := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames:     types.List{Null: true, ElemType: types.StringType},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			Policies: &EnrollmentPatternResourcePolicy{
				RFCEnforcement:       types.Bool{Value: true},
				CertificateOwnerRole: types.Int64{Value: 2},
			},
		}
		got := enrollmentPatternCreationAuditFields(ctx, created, types.Bool{Null: true})
		if !anyContains(got, "policies.rfc_enforcement") {
			t.Errorf("got %+v, want an entry for policies.rfc_enforcement", got)
		}
		if !anyContains(got, "policies.certificate_owner_role") {
			t.Errorf("got %+v, want an entry for policies.certificate_owner_role", got)
		}
	})

	t.Run("no policy entries when Policies is nil", func(t *testing.T) {
		t.Parallel()
		created := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames:     types.List{Null: true, ElemType: types.StringType},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
		}
		got := enrollmentPatternCreationAuditFields(ctx, created, types.Bool{Null: true})
		if anyContains(got, "policies.") {
			t.Errorf("got %+v, want no policies.* entries when Policies is nil", got)
		}
	})

	t.Run("values are escaped", func(t *testing.T) {
		t.Parallel()
		created := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames: types.List{
				ElemType: types.StringType,
				Elems:    []attr.Value{types.String{Value: "Administrator\nforged"}},
			},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
		}
		got := enrollmentPatternCreationAuditFields(ctx, created, types.Bool{Null: true})
		for _, entry := range got {
			if strings.Contains(entry, "\n") {
				t.Errorf("got %q, want no raw newline (CWE-117 escaping) in audit entry", entry)
			}
		}
	})

	// -----------------------------------------------------------------------
	// Regression test -- PR #210 full-review round 2 finding FIX-B:
	//
	// force_template_default was missing from enrollmentPatternCreationAudit-
	// Fields entirely, and even if referenced directly off `created` would
	// always read back "(null)" -- Create() force-resets
	// newState.ForceTemplateDefault to Null (it's never persisted
	// server-side) BEFORE calling this function. The value that was actually
	// submitted to the API must be sourced from the pre-reset plan value,
	// passed in as submittedForceTemplateDefault.
	// -----------------------------------------------------------------------

	t.Run("reports force_template_default sourced from the submitted value, not the reset state", func(t *testing.T) {
		t.Parallel()
		// created mirrors Create()'s newState AFTER the force-reset to Null
		// -- i.e. exactly what the function receives in practice.
		created := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames:     types.List{Null: true, ElemType: types.StringType},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			ForceTemplateDefault:    types.Bool{Null: true},
		}
		got := enrollmentPatternCreationAuditFields(ctx, created, types.Bool{Value: true})
		if !anyContains(got, "force_template_default: true") {
			t.Errorf(
				"got %+v, want an entry reporting force_template_default: true (the value actually submitted "+
					"to the API), not (null) (the post-reset state value)", got,
			)
		}
	})

	t.Run("reports force_template_default as (null) when never declared", func(t *testing.T) {
		t.Parallel()
		created := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames:     types.List{Null: true, ElemType: types.StringType},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			ForceTemplateDefault:    types.Bool{Null: true},
		}
		got := enrollmentPatternCreationAuditFields(ctx, created, types.Bool{Null: true})
		if !anyContains(got, "force_template_default: (null)") {
			t.Errorf("got %+v, want an entry reporting force_template_default: (null)", got)
		}
	})

	// -----------------------------------------------------------------------
	// Regression tests -- PR #210 full-review round 2 finding FIX-C:
	// policies.default_certificate_owner_override, policies.primary_key_
	// algorithms, and policies.alternative_key_algorithms were missing from
	// Create()'s audit trail too (see the equivalent Update()-path tests
	// above).
	// -----------------------------------------------------------------------

	t.Run("reports policies.default_certificate_owner_override, primary/alternative_key_algorithms", func(t *testing.T) {
		t.Parallel()
		created := KeyfactorEnrollmentPatternState{
			AssociatedRoleNames:     types.List{Null: true, ElemType: types.StringType},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			Policies: &EnrollmentPatternResourcePolicy{
				DefaultCertificateOwnerOverride: types.Bool{Value: true},
				PrimaryKeyAlgorithms: []EnrollmentPatternResourceAlgorithm{
					{Name: types.String{Value: "RSA"}},
				},
				AlternativeKeyAlgorithms: []EnrollmentPatternResourceAlgorithm{
					{Name: types.String{Value: "ECDSA"}},
				},
			},
		}
		got := enrollmentPatternCreationAuditFields(ctx, created, types.Bool{Null: true})
		if !anyContains(got, "policies.default_certificate_owner_override") {
			t.Errorf("got %+v, want an entry for policies.default_certificate_owner_override", got)
		}
		if !anyContains(got, "policies.primary_key_algorithms") {
			t.Errorf("got %+v, want an entry for policies.primary_key_algorithms", got)
		}
		if !anyContains(got, "policies.alternative_key_algorithms") {
			t.Errorf("got %+v, want an entry for policies.alternative_key_algorithms", got)
		}
	})
}

// TestUnitAlgorithmListLogString covers algorithmListLogString directly --
// the null-vs-non-nil-empty-aware renderer backing the new policies.
// primary_key_algorithms/alternative_key_algorithms audit-log entries (PR
// #210 full-review round 2 finding FIX-C).
func TestUnitAlgorithmListLogString(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	if got := algorithmListLogString(ctx, nil); got != "(null)" {
		t.Errorf("got %q, want (null) for a nil slice", got)
	}

	if got := algorithmListLogString(ctx, []EnrollmentPatternResourceAlgorithm{}); got != "[]" {
		t.Errorf("got %q, want [] for a non-nil empty slice", got)
	}

	got := algorithmListLogString(
		ctx, []EnrollmentPatternResourceAlgorithm{
			{
				Name:       types.String{Value: "RSA"},
				BitLengths: types.List{ElemType: types.Int64Type, Elems: []attr.Value{types.Int64{Value: 2048}}},
				Curves:     types.List{Null: true, ElemType: types.StringType},
			},
		},
	)
	if !strings.Contains(got, `"RSA"`) {
		t.Errorf("got %q, want the algorithm name %%q-escaped", got)
	}

	// CWE-117 regression: an embedded newline in the algorithm name must be
	// escaped, not passed through raw.
	injected := algorithmListLogString(
		ctx, []EnrollmentPatternResourceAlgorithm{
			{Name: types.String{Value: "RSA\nforged"}},
		},
	)
	if strings.Contains(injected, "\n") {
		t.Errorf("got %q, want no raw newline in rendered log value", injected)
	}
}
