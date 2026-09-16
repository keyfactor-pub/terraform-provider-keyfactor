package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: declared-empty list clearing in request builders.
//
// buildEnrollmentPatternUpdateRequest/buildEnrollmentPatternCreateRequest
// gated Regexes/MetadataFields/Defaults/EnrollmentFields (and
// buildEnrollmentPatternPolicyRequest gated PrimaryKeyAlgorithms/
// AlternativeKeyAlgorithms) on `len(plan.X) > 0`, which treats a
// plan-declared empty list (e.g. `regexes = []`, intended to CLEAR a
// previously-set list back to empty) identically to an undeclared one --
// both fail the `> 0` test -- silently omitting the field from the request
// instead of clearing it server-side.
//
// The initial triage hypothesis was that this couldn't be fixed cleanly
// because the SDK request models tag these fields `json:"...,omitempty"` on
// a plain (non-pointer) []T, and stdlib encoding/json's own omitempty
// semantics drop a zero-length slice regardless of nil-ness. That hypothesis
// turned out to be wrong: these generated models override MarshalJSON with a
// hand-written ToMap() (see model_enrollment_patterns_enrollment_pattern_
// policy_request.go / model_enrollment_patterns_enrollment_pattern_request.go
// in the vendored SDK) that checks `o.Field != nil`, not `len(o.Field) > 0` --
// so a non-nil empty slice IS how this SDK expresses "send an explicit empty
// array." The actual fix has two parts:
//  1. The `len(plan.X) > 0` gates below must become `plan.X != nil` so a
//     plan-declared empty list reaches the setter at all.
//  2. The builder helpers themselves (buildEnrollmentPatternRegexesRequest
//     etc.) must preserve nil-vs-non-nil-empty on their own output, or they
//     would silently collapse a non-nil-empty input back to nil via the same
//     append-onto-nil-slice pattern already fixed for the response
//     conversion helpers (see resource_keyfactor_enrollment_pattern_response_
//     conversion_unit_test.go).
// ---------------------------------------------------------------------------

func TestUnitEnrollmentPatternRequestBuildersPreserveEmptyVsNil(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("buildEnrollmentPatternRegexesRequest", func(t *testing.T) {
		t.Parallel()
		if got := buildEnrollmentPatternRegexesRequest(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil (undeclared -- omit from request)", got)
		}
		got := buildEnrollmentPatternRegexesRequest([]EnrollmentPatternResourceRegex{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice (declared `regexes = []` -- must clear)")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("buildEnrollmentPatternMetadataFieldsRequest", func(t *testing.T) {
		t.Parallel()
		if got := buildEnrollmentPatternMetadataFieldsRequest(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := buildEnrollmentPatternMetadataFieldsRequest([]EnrollmentPatternResourceMetadataField{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("buildEnrollmentPatternDefaultsRequest", func(t *testing.T) {
		t.Parallel()
		if got := buildEnrollmentPatternDefaultsRequest(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := buildEnrollmentPatternDefaultsRequest([]EnrollmentPatternResourceDefault{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("buildEnrollmentPatternFieldsRequest", func(t *testing.T) {
		t.Parallel()
		if got := buildEnrollmentPatternFieldsRequest(ctx, nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := buildEnrollmentPatternFieldsRequest(ctx, []EnrollmentPatternResourceField{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("buildAlgorithmDataRequestV2List", func(t *testing.T) {
		t.Parallel()
		if got := buildAlgorithmDataRequestV2List(ctx, nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := buildAlgorithmDataRequestV2List(ctx, []EnrollmentPatternResourceAlgorithm{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})
}

// TestUnitBuildEnrollmentPatternUpdateRequestClearsExplicitEmptyLists is the
// end-to-end regression test for F2: a plan with non-nil-but-empty Regexes/
// MetadataFields/Defaults/EnrollmentFields (matching `regexes = []` etc.
// declared in config, distinguishable from "undeclared" only by nilness --
// see KeyfactorEnrollmentPatternState's Go slice fields) must produce a
// request whose ToMap() includes each field as an explicit `[]`, not omit it.
// Before the fix, the `len() > 0` gates in buildEnrollmentPatternUpdateRequest
// omitted the field entirely, leaving Command's stored value for that field
// unchanged instead of clearing it -- silently defeating the user's declared
// `= []`.
func TestUnitBuildEnrollmentPatternUpdateRequestClearsExplicitEmptyLists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	plan := KeyfactorEnrollmentPatternState{
		Name:             types.String{Value: "test-pattern"},
		Regexes:          []EnrollmentPatternResourceRegex{},
		MetadataFields:   []EnrollmentPatternResourceMetadataField{},
		Defaults:         []EnrollmentPatternResourceDefault{},
		EnrollmentFields: []EnrollmentPatternResourceField{},
		Policies: &EnrollmentPatternResourcePolicy{
			PrimaryKeyAlgorithms:     []EnrollmentPatternResourceAlgorithm{},
			AlternativeKeyAlgorithms: []EnrollmentPatternResourceAlgorithm{},
		},
	}

	req := buildEnrollmentPatternUpdateRequest(ctx, plan)

	body, err := req.ToMap()
	if err != nil {
		t.Fatalf("ToMap() error: %v", err)
	}

	for _, key := range []string{"Regexes", "MetadataFields", "Defaults", "EnrollmentFields"} {
		v, ok := body[key]
		if !ok {
			t.Errorf(
				"%s: missing from request body -- an explicitly declared empty list must be sent as `[]` "+
					"to clear the field server-side, not omitted (which leaves the prior value unchanged)", key,
			)
			continue
		}
		if v == nil {
			t.Errorf("%s: present but nil in request body, want a non-nil empty slice", key)
		}
	}

	policyBody, err := req.Policies.ToMap()
	if err != nil {
		t.Fatalf("Policies.ToMap() error: %v", err)
	}
	for _, key := range []string{"PrimaryKeyAlgorithms", "AlternativeKeyAlgorithms"} {
		v, ok := policyBody[key]
		if !ok {
			t.Errorf("Policies.%s: missing from request body, want an explicit `[]`", key)
			continue
		}
		if v == nil {
			t.Errorf("Policies.%s: present but nil in request body, want a non-nil empty slice", key)
		}
	}
}

// TestUnitBuildEnrollmentPatternUpdateRequestOmitsUndeclaredLists is the
// control case for the same fix: a plan with truly nil (undeclared) list
// fields must still OMIT them from the request entirely, preserving the
// existing "leave unchanged" behavior for fields the user never mentioned.
func TestUnitBuildEnrollmentPatternUpdateRequestOmitsUndeclaredLists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	plan := KeyfactorEnrollmentPatternState{
		Name: types.String{Value: "test-pattern"},
		// Regexes/MetadataFields/Defaults/EnrollmentFields/Policies left at
		// Go's zero value (nil) -- simulating an undeclared attribute.
	}

	req := buildEnrollmentPatternUpdateRequest(ctx, plan)

	body, err := req.ToMap()
	if err != nil {
		t.Fatalf("ToMap() error: %v", err)
	}

	for _, key := range []string{"Regexes", "MetadataFields", "Defaults", "EnrollmentFields"} {
		if _, ok := body[key]; ok {
			t.Errorf("%s: present in request body, want omitted (field was never declared)", key)
		}
	}

	policyBody, err := req.Policies.ToMap()
	if err != nil {
		t.Fatalf("Policies.ToMap() error: %v", err)
	}
	for _, key := range []string{"PrimaryKeyAlgorithms", "AlternativeKeyAlgorithms"} {
		if _, ok := policyBody[key]; ok {
			t.Errorf("Policies.%s: present in request body, want omitted", key)
		}
	}
}
