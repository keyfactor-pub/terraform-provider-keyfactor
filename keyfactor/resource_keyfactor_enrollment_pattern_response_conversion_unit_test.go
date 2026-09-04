package keyfactor

import (
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: nil-vs-non-nil-empty response conversion.
//
// enrollmentPatternFieldsToState (enrollment_fields.options) and
// algorithmDataResponseToResourceEntry (policies.primary_key_algorithms/
// alternative_key_algorithms .bit_lengths/.curves) collapsed a server
// response's zero-length slice to types.List{Null: true} unconditionally,
// even when the underlying SDK field is a plain (non-nullable-wrapper)
// []string/[]int32 that is non-nil precisely when the server's JSON response
// carried an actual `[]` for that key -- which only happens when the config
// declared the list explicitly (including as empty, e.g. `options = []` or
// `curves = []` for an RSA entry that legitimately has none).
//
// Repro: config declares `enrollment_fields { name = "x" data_type = 1
// options = [] }`. Plan holds a known non-null empty list for `options`
// (Optional, not Computed -- no plan modifier can intervene). Create/Update's
// response conversion wrote back Null instead, so Terraform aborted the
// apply with "Provider produced inconsistent result after apply:
// .enrollment_fields[0].options: was [], but now null" (and the equivalent
// for primary_key_algorithms[].curves / .bit_lengths, which are
// Optional+Computed with tfsdk.UseStateForUnknown() -- a plan modifier that
// only substitutes when the PLAN value is Unknown, never when it's a known
// non-null empty list).
//
// This mirrors the identical bug class already fixed for
// certStoreTypeDefToState (see
// resource_keyfactor_certificate_store_type_entry_parameters_unit_test.go):
// a nil Go slice (server truly omitted/nulled the key) must stay Null, but a
// non-nil Go slice -- even zero-length -- must become a known, non-null
// empty types.List.
// ---------------------------------------------------------------------------

// TestUnitEnrollmentPatternFieldsToStatePreservesEmptyOptions is the direct
// regression test. Before the fix, a non-nil empty
// f.Options ([]string{}) -- the shape the server sends back when the
// config declared `options = []` -- is collapsed to Null instead of a known
// empty list.
func TestUnitEnrollmentPatternFieldsToStatePreservesEmptyOptions(t *testing.T) {
	t.Parallel()

	t.Run("non-nil empty Options must become a known non-null empty list", func(t *testing.T) {
		t.Parallel()

		name := "x"
		dataType := v1.CSSCMSCoreEnumsTemplateEnrollmentFieldType(1)
		fields := []v1.EnrollmentPatternsEnrollmentPatternFieldResponse{
			{
				Name:     *v1.NewNullableString(&name),
				DataType: &dataType,
				Options:  []string{}, // non-nil, zero-length -- server echoed an explicit `[]`
			},
		}

		result := enrollmentPatternFieldsToState(fields)

		if len(result) != 1 {
			t.Fatalf("want 1 field, got %d", len(result))
		}
		got := result[0].Options
		if got.Null {
			t.Errorf(
				"Options = %+v, want a known non-null empty list (server returned a non-nil empty array, matching "+
					"a config-declared `options = []`); Null clobbers a known-empty plan value and crashes the apply "+
					"with \"Provider produced inconsistent result after apply\"",
				got,
			)
		}
		if got.Unknown {
			t.Errorf("Options = %+v, want known (not Unknown)", got)
		}
		if got.ElemType != types.StringType {
			t.Errorf("Options.ElemType = %v, want %v", got.ElemType, types.StringType)
		}
		if len(got.Elems) != 0 {
			t.Errorf("Options.Elems = %+v, want empty", got.Elems)
		}
	})

	t.Run("nil Options (server omitted/nulled the key) must stay Null", func(t *testing.T) {
		t.Parallel()

		name := "x"
		dataType := v1.CSSCMSCoreEnumsTemplateEnrollmentFieldType(1)
		fields := []v1.EnrollmentPatternsEnrollmentPatternFieldResponse{
			{
				Name:     *v1.NewNullableString(&name),
				DataType: &dataType,
				Options:  nil,
			},
		}

		result := enrollmentPatternFieldsToState(fields)

		if len(result) != 1 {
			t.Fatalf("want 1 field, got %d", len(result))
		}
		got := result[0].Options
		if !got.Null {
			t.Errorf("Options = %+v, want Null (server truly omitted the field -- matches an undeclared config)", got)
		}
		if got.ElemType != types.StringType {
			t.Errorf("Options.ElemType = %v, want %v", got.ElemType, types.StringType)
		}
	})

	t.Run("populated Options round-trips unchanged", func(t *testing.T) {
		t.Parallel()

		name := "x"
		dataType := v1.CSSCMSCoreEnumsTemplateEnrollmentFieldType(2)
		fields := []v1.EnrollmentPatternsEnrollmentPatternFieldResponse{
			{
				Name:     *v1.NewNullableString(&name),
				DataType: &dataType,
				Options:  []string{"a", "b"},
			},
		}

		result := enrollmentPatternFieldsToState(fields)

		got := result[0].Options
		if got.Null || got.Unknown {
			t.Errorf("Options = %+v, want known non-null", got)
		}
		if len(got.Elems) != 2 {
			t.Errorf("Options.Elems = %+v, want 2 elements", got.Elems)
		}
	})
}

// TestUnitAlgorithmDataResponseToResourceEntryPreservesEmptyBitLengthsAndCurves
// is the direct regression test. Before the fix, non-nil
// empty a.BitLengths/a.Curves -- the shape the server sends back when the
// config declared `bit_lengths = []`/`curves = []` (legitimate for an RSA
// entry, which has no curves) -- are collapsed to Null instead of a known
// empty list.
func TestUnitAlgorithmDataResponseToResourceEntryPreservesEmptyBitLengthsAndCurves(t *testing.T) {
	t.Parallel()

	t.Run("non-nil empty BitLengths/Curves must become known non-null empty lists", func(t *testing.T) {
		t.Parallel()

		name := "RSA"
		a := v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse{
			Name:       *v1.NewNullableString(&name),
			BitLengths: []int32{},
			Curves:     []string{},
		}

		entry := algorithmDataResponseToResourceEntry(a)

		if entry.BitLengths.Null {
			t.Errorf(
				"BitLengths = %+v, want a known non-null empty list; Null clobbers a known-empty plan value "+
					"(UseStateForUnknown only substitutes on an Unknown plan, never a known empty list) and "+
					"crashes the apply with \"Provider produced inconsistent result after apply\"",
				entry.BitLengths,
			)
		}
		if entry.BitLengths.Unknown {
			t.Errorf("BitLengths = %+v, want known", entry.BitLengths)
		}
		if entry.BitLengths.ElemType != types.Int64Type {
			t.Errorf("BitLengths.ElemType = %v, want %v", entry.BitLengths.ElemType, types.Int64Type)
		}

		if entry.Curves.Null {
			t.Errorf(
				"Curves = %+v, want a known non-null empty list (same reasoning as BitLengths above)", entry.Curves,
			)
		}
		if entry.Curves.Unknown {
			t.Errorf("Curves = %+v, want known", entry.Curves)
		}
		if entry.Curves.ElemType != types.StringType {
			t.Errorf("Curves.ElemType = %v, want %v", entry.Curves.ElemType, types.StringType)
		}
	})

	t.Run("nil BitLengths/Curves (server omitted/nulled the key) must stay Null", func(t *testing.T) {
		t.Parallel()

		name := "RSA"
		a := v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse{
			Name:       *v1.NewNullableString(&name),
			BitLengths: nil,
			Curves:     nil,
		}

		entry := algorithmDataResponseToResourceEntry(a)

		if !entry.BitLengths.Null {
			t.Errorf("BitLengths = %+v, want Null (server truly omitted the field)", entry.BitLengths)
		}
		if entry.BitLengths.ElemType != types.Int64Type {
			t.Errorf("BitLengths.ElemType = %v, want %v", entry.BitLengths.ElemType, types.Int64Type)
		}
		if !entry.Curves.Null {
			t.Errorf("Curves = %+v, want Null (server truly omitted the field)", entry.Curves)
		}
		if entry.Curves.ElemType != types.StringType {
			t.Errorf("Curves.ElemType = %v, want %v", entry.Curves.ElemType, types.StringType)
		}
	})

	t.Run("populated BitLengths/Curves round-trip unchanged", func(t *testing.T) {
		t.Parallel()

		name := "ECDSA"
		a := v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse{
			Name:       *v1.NewNullableString(&name),
			BitLengths: []int32{256, 384},
			Curves:     []string{"P256", "P384"},
		}

		entry := algorithmDataResponseToResourceEntry(a)

		if entry.BitLengths.Null || entry.BitLengths.Unknown || len(entry.BitLengths.Elems) != 2 {
			t.Errorf("BitLengths = %+v, want known non-null with 2 elements", entry.BitLengths)
		}
		if entry.Curves.Null || entry.Curves.Unknown || len(entry.Curves.Elems) != 2 {
			t.Errorf("Curves = %+v, want known non-null with 2 elements", entry.Curves)
		}
	})
}

// ---------------------------------------------------------------------------
// Regression tests: nil-vs-non-nil-empty CertificateAuthorities.
//
// The identical bug class fixed above for enrollmentPatternFieldsToState's
// nested Options / algorithmDataResponseToResourceEntry's nested
// BitLengths/Curves was still present in 7 more places, all of which build
// their result by appending onto a nil-initialized Go slice:
//
//	var result []T
//	for _, x := range serverSlice {
//		result = append(result, ...)
//	}
//	return result
//
// This collapses BOTH "server truly omitted the field" (serverSlice is
// Go-nil) AND "server returned an explicit empty array" (serverSlice is
// non-nil, zero-length -- which only happens when the config declared the
// list explicitly, e.g. `regexes = []`) to the same Go-nil result, because a
// zero-iteration range loop never touches the nil-initialized `result`
// variable. terraform-plugin-framework's reflection layer encodes a nil Go
// slice as a null list, so a legitimate `regexes = []` collapses back to
// null on the very next Read/Update response, crashing the apply with
// "Provider produced inconsistent result after apply." The corresponding
// server response fields (AssociatedRoles, CertificateAuthorities, Regexes,
// MetadataFields, Defaults, EnrollmentFields, PrimaryKeyAlgorithms,
// AlternativeKeyAlgorithms) are all plain (non-nullable-wrapper) slices
// tagged `json:"...,omitempty"` on their respective SDK response models --
// confirmed non-nil precisely when the server's JSON carried an actual `[]`
// for that key, exactly like Options/BitLengths/Curves above.
//
// Fix mirrors certStoreTypeDefToState: produce a non-nil
// (possibly zero-length) result whenever the input is non-nil, and nil only
// when the input is truly nil.
// ---------------------------------------------------------------------------

func TestUnitEnrollmentPatternOuterListConversionsPreserveEmptyVsNil(t *testing.T) {
	t.Parallel()

	t.Run("enrollmentPatternAssociatedRolesToState", func(t *testing.T) {
		t.Parallel()
		if got := enrollmentPatternAssociatedRolesToState(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil (server omitted the field)", got)
		}
		got := enrollmentPatternAssociatedRolesToState([]v1.EnrollmentPatternsEnrollmentPatternAssociatedRoleResponse{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice (server returned an explicit `[]`)")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("enrollmentPatternCAsToState", func(t *testing.T) {
		t.Parallel()
		if got := enrollmentPatternCAsToState(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := enrollmentPatternCAsToState([]v1.EnrollmentPatternsEnrollmentPatternCAResponse{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("enrollmentPatternRegexesToState", func(t *testing.T) {
		t.Parallel()
		if got := enrollmentPatternRegexesToState(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := enrollmentPatternRegexesToState([]v1.EnrollmentPatternsEnrollmentPatternRegexesResponse{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("enrollmentPatternMetadataFieldsToState", func(t *testing.T) {
		t.Parallel()
		if got := enrollmentPatternMetadataFieldsToState(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := enrollmentPatternMetadataFieldsToState([]v1.EnrollmentPatternsEnrollmentPatternMetadataFieldResponse{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("enrollmentPatternDefaultsToState", func(t *testing.T) {
		t.Parallel()
		if got := enrollmentPatternDefaultsToState(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := enrollmentPatternDefaultsToState([]v1.EnrollmentPatternsEnrollmentPatternDefaultResponse{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("enrollmentPatternFieldsToState outer EnrollmentFields slice", func(t *testing.T) {
		t.Parallel()
		if got := enrollmentPatternFieldsToState(nil); got != nil {
			t.Errorf("nil input: got %+v, want nil", got)
		}
		got := enrollmentPatternFieldsToState([]v1.EnrollmentPatternsEnrollmentPatternFieldResponse{})
		if got == nil {
			t.Error("non-nil empty input: got nil, want a non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("non-nil empty input: got %+v, want length 0", got)
		}
	})

	t.Run("enrollmentPatternPolicyResponseToState outer PrimaryKeyAlgorithms/AlternativeKeyAlgorithms slices", func(t *testing.T) {
		t.Parallel()

		// nil PrimaryKeyAlgorithms/AlternativeKeyAlgorithms -- server omitted
		// both -- must stay nil in state.
		nilResult := enrollmentPatternPolicyResponseToState(&v1.EnrollmentPatternsEnrollmentPatternPolicyResponse{})
		if nilResult.PrimaryKeyAlgorithms != nil {
			t.Errorf("PrimaryKeyAlgorithms = %+v, want nil", nilResult.PrimaryKeyAlgorithms)
		}
		if nilResult.AlternativeKeyAlgorithms != nil {
			t.Errorf("AlternativeKeyAlgorithms = %+v, want nil", nilResult.AlternativeKeyAlgorithms)
		}

		// non-nil empty PrimaryKeyAlgorithms/AlternativeKeyAlgorithms --
		// server echoed back an explicit `[]` (matching a config-declared
		// `primary_key_algorithms = []`) -- must become a non-nil empty
		// slice, not nil.
		emptyResult := enrollmentPatternPolicyResponseToState(
			&v1.EnrollmentPatternsEnrollmentPatternPolicyResponse{
				PrimaryKeyAlgorithms:     []v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse{},
				AlternativeKeyAlgorithms: []v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse{},
			},
		)
		if emptyResult.PrimaryKeyAlgorithms == nil {
			t.Error(
				"PrimaryKeyAlgorithms: got nil, want a non-nil empty slice (server returned an explicit `[]`); " +
					"nil clobbers a known-empty plan value and crashes the apply with \"Provider produced " +
					"inconsistent result after apply\"",
			)
		}
		if len(emptyResult.PrimaryKeyAlgorithms) != 0 {
			t.Errorf("PrimaryKeyAlgorithms = %+v, want length 0", emptyResult.PrimaryKeyAlgorithms)
		}
		if emptyResult.AlternativeKeyAlgorithms == nil {
			t.Error("AlternativeKeyAlgorithms: got nil, want a non-nil empty slice")
		}
		if len(emptyResult.AlternativeKeyAlgorithms) != 0 {
			t.Errorf("AlternativeKeyAlgorithms = %+v, want length 0", emptyResult.AlternativeKeyAlgorithms)
		}

		// populated PrimaryKeyAlgorithms round-trips unchanged.
		name := "RSA"
		populatedResult := enrollmentPatternPolicyResponseToState(
			&v1.EnrollmentPatternsEnrollmentPatternPolicyResponse{
				PrimaryKeyAlgorithms: []v1.EnrollmentPatternsAlgorithmsAlgorithmDataResponse{
					{Name: *v1.NewNullableString(&name)},
				},
			},
		)
		if len(populatedResult.PrimaryKeyAlgorithms) != 1 {
			t.Errorf("PrimaryKeyAlgorithms = %+v, want 1 entry", populatedResult.PrimaryKeyAlgorithms)
		}
	})
}
