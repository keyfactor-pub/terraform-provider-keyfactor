package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression test -- PR #210 full-review round 2 finding FIX-D:
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
// Regression test -- PR #210 full-review round 2 finding FIX-F:
//
// The previous match logic OR'd a name-equality check with an
// ID-equality check with no priority between them, so "first match wins"
// across a server-ordered list could silently resolve `identifier` to the
// wrong pattern -- e.g. pattern A (ID=2, Name="5") and pattern B (ID=5,
// Name="Default") both exist; identifier = "5" intends to look up pattern B
// by ID, but matches pattern A's name first if Command returns it earlier
// in the list.
//
// enrollmentPatternMatchesIdentifier enforces a strict priority instead: if
// identifier parses as an integer, match ONLY on ID; otherwise match ONLY
// on name.
// ---------------------------------------------------------------------------

func TestUnitEnrollmentPatternMatchesIdentifier(t *testing.T) {
	t.Parallel()

	t.Run("numeric identifier matches by ID only, even when another pattern's name collides", func(t *testing.T) {
		t.Parallel()

		// Pattern A: ID=2, Name="5" -- a name that looks like an ID.
		// Pattern B: ID=5, Name="Default" -- the pattern identifier="5"
		// actually means to select, by ID.
		if enrollmentPatternMatchesIdentifier("5", 2, "5") {
			t.Error("got true, want false -- a numeric identifier must not match on Name, even if Name looks numeric")
		}
		if !enrollmentPatternMatchesIdentifier("5", 5, "Default") {
			t.Error("got false, want true -- a numeric identifier must match the pattern whose ID equals it")
		}
	})

	t.Run("non-numeric identifier matches by name only", func(t *testing.T) {
		t.Parallel()

		if !enrollmentPatternMatchesIdentifier("Default", 5, "Default") {
			t.Error("got false, want true -- a non-numeric identifier must match the pattern whose Name equals it")
		}
		if enrollmentPatternMatchesIdentifier("Default", 99, "Other") {
			t.Error("got true, want false for a non-matching name")
		}
	})

	t.Run("simulated list walk resolves by documented precedence, not list order", func(t *testing.T) {
		t.Parallel()

		type candidate struct {
			id   int
			name string
		}
		// Pattern A appears FIRST in the list and has Name == "5" (the
		// identifier we're looking up); pattern B appears SECOND and has
		// ID == 5. Before the fix, "first match wins" logic would return A
		// (matching on name) since it's iterated first. The fix must return
		// B, since a numeric identifier is documented to match on ID only.
		patterns := []candidate{
			{id: 2, name: "5"},
			{id: 5, name: "Default"},
		}

		identifier := "5"
		var matchedID int
		var matchedName string
		found := false
		for _, p := range patterns {
			if enrollmentPatternMatchesIdentifier(identifier, p.id, p.name) {
				matchedID = p.id
				matchedName = p.name
				found = true
				break
			}
		}

		if !found {
			t.Fatal("expected a match, got none")
		}
		if matchedID != 5 || matchedName != "Default" {
			t.Errorf(
				"got match {id:%d,name:%q}, want {id:5,name:%q} -- a numeric identifier must resolve to the "+
					"pattern matching by ID, not the pattern earlier in the list matching by name",
				matchedID, matchedName, "Default",
			)
		}
	})
}
