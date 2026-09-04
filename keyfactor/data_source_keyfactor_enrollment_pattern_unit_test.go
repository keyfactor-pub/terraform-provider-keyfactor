package keyfactor

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression test:
//
// dataSourceEnrollmentPattern.Read unconditionally dereferenced
// pattern.AllowedEnrollmentTypes (a *int on the legacy keyfactor-go-client v3
// API model), which is nil whenever Command omits the key from the response
// -- a real, reachable case since the corresponding resource attribute
// (allowed_enrollment_types) is Optional+Computed. Every other pointer field
// in the same Read() function is nil-checked before use; this was the one
// field that was missed, and it panicked unconditionally (both
// dereferences) on `terraform plan`/`refresh` against such a pattern.
//
// allowedEnrollmentTypesPtrToTfInt64 is the pure conversion function
// factored out of Read() so this can be verified directly, without standing
// up an HTTP mock for the full Read() call.
// ---------------------------------------------------------------------------

func TestUnitAllowedEnrollmentTypesPtrToTfInt64(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer does not panic and produces Null", func(t *testing.T) {
		t.Parallel()

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("allowedEnrollmentTypesPtrToTfInt64(nil) panicked: %v", r)
			}
		}()

		got := allowedEnrollmentTypesPtrToTfInt64(nil)
		want := types.Int64{Null: true}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("non-nil pointer produces the pointed-to value", func(t *testing.T) {
		t.Parallel()

		v := 3
		got := allowedEnrollmentTypesPtrToTfInt64(&v)
		if got.Null || got.Value != 3 {
			t.Errorf("got %+v, want {Value: 3, Null: false}", got)
		}
	})

	t.Run("non-nil pointer to the isNullId sentinel value produces Null", func(t *testing.T) {
		t.Parallel()

		// isNullId's sentinel (see helpers.go) is the legacy v3 API client's
		// way of representing "no value" for a plain (non-pointer) int
		// field elsewhere in this same response model; preserve that
		// behavior for the pointer case too.
		v := 0
		got := allowedEnrollmentTypesPtrToTfInt64(&v)
		if !got.Null {
			t.Errorf("got %+v, want Null for the isNullId sentinel value", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Regression tests:
//
// An earlier design replaced an ambiguous "name == identifier OR id ==
// identifier" match with a strict, strconv.Atoi-gated priority: if
// identifier parses as an integer, match ONLY on ID; otherwise match ONLY
// on name. That over-corrected two ways:
//   - a pattern literally NAMED "2025" became unreachable by name (or
//     worse, silently resolved to a DIFFERENT pattern whose ID happens to
//     be 2025), purely because its name looks numeric.
//   - identifier = "007" would resolve, via strconv.Atoi, to a pattern
//     with ID 7 -- but no pattern is literally named "007", so this is
//     surprising if the user actually meant to look up a pattern NAMED
//     "007".
//
// enrollmentPatternResolveIdentifier restores name-or-ID semantics:
// an exact NAME match wins deterministically;
// a canonical ID-string match (fmt.Sprint(id) == identifier, so "007"
// never matches ID 7) is the fallback; a genuine match on both for two
// DIFFERENT patterns is ambiguous and returns an error rather than
// silently picking one.
// ---------------------------------------------------------------------------

func TestUnitEnrollmentPatternResolveIdentifier(t *testing.T) {
	t.Parallel()

	t.Run("exact name match resolves, even when another pattern's ID equals the identifier", func(t *testing.T) {
		t.Parallel()

		// Pattern A: ID=2, Name="5" -- a name that looks like an ID, and IS
		// the identifier being looked up.
		// Pattern B: ID=5, Name="Default" -- ID happens to equal the
		// identifier too, but the name match on A takes precedence.
		candidates := []enrollmentPatternCandidate{
			{ID: 2, Name: "5"},
			{ID: 5, Name: "Default"},
		}
		idx, err := enrollmentPatternResolveIdentifier("5", candidates)
		if err == nil {
			t.Fatalf(
				"got idx=%d, err=nil, want an ambiguity error -- \"5\" genuinely matches pattern A by name AND "+
					"pattern B by ID, which is exactly the case that must be flagged, not silently resolved",
				idx,
			)
		}
		if !strings.Contains(err.Error(), "ambiguous") {
			t.Errorf("err = %q, want it to mention \"ambiguous\"", err.Error())
		}
	})

	t.Run("a pattern literally named with a number is reachable by name", func(t *testing.T) {
		t.Parallel()

		// No OTHER pattern has ID 2025, so there is no ambiguity -- this is
		// exactly the case the old strconv.Atoi-gated design broke: it
		// would have matched ONLY on ID (since "2025" parses as an
		// integer), found no pattern with ID 2025, and reported "not
		// found" even though a pattern named "2025" exists.
		candidates := []enrollmentPatternCandidate{
			{ID: 3, Name: "2025"},
		}
		idx, err := enrollmentPatternResolveIdentifier("2025", candidates)
		if err != nil {
			t.Fatalf("err = %v, want no error -- pattern named \"2025\" must be reachable by name", err)
		}
		if idx != 0 {
			t.Errorf("idx = %d, want 0", idx)
		}
	})

	t.Run(`"007" matches a pattern literally named "007", never a pattern with ID 7`, func(t *testing.T) {
		t.Parallel()

		candidates := []enrollmentPatternCandidate{
			{ID: 99, Name: "007"},
			{ID: 7, Name: "SevenPattern"},
		}
		idx, err := enrollmentPatternResolveIdentifier("007", candidates)
		if err != nil {
			t.Fatalf(`err = %v, want no error -- "007" must resolve to the pattern literally named "007"`, err)
		}
		if idx != 0 {
			t.Errorf("idx = %d, want 0 (the pattern named \"007\", not the pattern with ID 7)", idx)
		}
	})

	t.Run("canonical ID-string match resolves when no name matches", func(t *testing.T) {
		t.Parallel()

		candidates := []enrollmentPatternCandidate{
			{ID: 5, Name: "Default"},
		}
		idx, err := enrollmentPatternResolveIdentifier("5", candidates)
		if err != nil {
			t.Fatalf("err = %v, want no error", err)
		}
		if idx != 0 {
			t.Errorf("idx = %d, want 0", idx)
		}
	})

	t.Run("no match at all is a not-found error", func(t *testing.T) {
		t.Parallel()

		candidates := []enrollmentPatternCandidate{
			{ID: 5, Name: "Default"},
		}
		_, err := enrollmentPatternResolveIdentifier("NoSuchPattern", candidates)
		if err == nil {
			t.Fatal("err = nil, want a not-found error")
		}
	})

	t.Run("name and ID match resolving to the SAME pattern is not ambiguous", func(t *testing.T) {
		t.Parallel()

		candidates := []enrollmentPatternCandidate{
			{ID: 5, Name: "5"},
		}
		idx, err := enrollmentPatternResolveIdentifier("5", candidates)
		if err != nil {
			t.Fatalf("err = %v, want no error -- both matches point at the same pattern", err)
		}
		if idx != 0 {
			t.Errorf("idx = %d, want 0", idx)
		}
	})

	t.Run("list order does not affect resolution", func(t *testing.T) {
		t.Parallel()

		// Same ambiguous scenario as the first sub-test, but with the
		// ID-matching pattern listed FIRST -- the result (an ambiguity
		// error) must not depend on list order.
		candidates := []enrollmentPatternCandidate{
			{ID: 5, Name: "Default"},
			{ID: 2, Name: "5"},
		}
		_, err := enrollmentPatternResolveIdentifier("5", candidates)
		if err == nil {
			t.Fatal("err = nil, want an ambiguity error regardless of list order")
		}
	})
}
