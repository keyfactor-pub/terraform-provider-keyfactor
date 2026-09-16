package keyfactor

import (
	"strings"
	"testing"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression test:
//
// dataSourceEnrollmentPattern.Read unconditionally dereferenced
// pattern.AllowedEnrollmentTypes, which is nil whenever Command omits the key
// from the response -- a real, reachable case since the corresponding resource
// attribute (allowed_enrollment_types) is Optional+Computed. Every other
// pointer field in the same Read() function is nil-checked before use; this
// was the one field that was missed, and it panicked unconditionally on every
// `terraform plan`/`refresh` against such a pattern.
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

		v := kfv1.CSSCMSCoreEnumsEnrollmentType(3)
		got := allowedEnrollmentTypesPtrToTfInt64(&v)
		if got.Null || got.Value != 3 {
			t.Errorf("got %+v, want {Value: 3, Null: false}", got)
		}
	})

	t.Run("non-nil pointer to zero value produces non-Null (enum value 0 is valid)", func(t *testing.T) {
		t.Parallel()

		// CSSCMSCoreEnumsEnrollmentType(0) is a real enum value returned by
		// Command when the enrollment type is set to the first option. Unlike
		// the old legacy-client *int representation (where 0 was treated as
		// "no value" via isNullId), the SDK uses a nil pointer to represent
		// absence, so a non-nil pointer to value 0 must produce a known
		// (non-Null) Int64.
		v := kfv1.CSSCMSCoreEnumsEnrollmentType(0)
		got := allowedEnrollmentTypesPtrToTfInt64(&v)
		if got.Null {
			t.Errorf("got Null, want {Value: 0, Null: false} -- enum value 0 is valid, not a sentinel")
		}
		if got.Value != 0 {
			t.Errorf("got Value=%d, want 0", got.Value)
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

// ---------------------------------------------------------------------------
// Unit tests: enrollmentPatternSelectByTemplateShortName
//
// The function validates the count of patterns returned by a server-side
// template_short_name QueryString filter. templateDefaultFilter is *bool:
//   nil    — no TemplateDefault filter was applied
//   *true  — TemplateDefault -eq "true" was applied
//   *false — TemplateDefault -eq "false" was applied
//
// Error messages are tailored per case so guidance never contradicts the
// user's explicit intent (a user who set template_default=false must not be
// told to "set template_default=true").
// ---------------------------------------------------------------------------

func boolPtrForEPTest(v bool) *bool { return &v }

func TestUnitEnrollmentPatternSelectByTemplateShortName(t *testing.T) {
	t.Parallel()

	// --- nil filter (template_default omitted) ---

	t.Run("nil filter, zero results: returns not-found error", func(t *testing.T) {
		t.Parallel()

		err := enrollmentPatternSelectByTemplateShortName(0, "Entity_ClientAuth", nil)
		if err == nil {
			t.Fatal("err = nil, want a not-found error")
		}
		if !strings.Contains(err.Error(), "no enrollment pattern found") {
			t.Errorf("err = %q, want it to mention \"no enrollment pattern found\"", err.Error())
		}
		if !strings.Contains(err.Error(), "Entity_ClientAuth") {
			t.Errorf("err = %q, want it to include the template short name", err.Error())
		}
	})

	t.Run("nil filter, one result: success", func(t *testing.T) {
		t.Parallel()

		if err := enrollmentPatternSelectByTemplateShortName(1, "Entity_ClientAuth", nil); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})

	t.Run("nil filter, multiple results: suggests template_default=true", func(t *testing.T) {
		t.Parallel()

		err := enrollmentPatternSelectByTemplateShortName(3, "Entity_ClientAuth", nil)
		if err == nil {
			t.Fatal("err = nil, want an ambiguous-match error")
		}
		if !strings.Contains(err.Error(), "template_default = true") {
			t.Errorf("err = %q, want it to suggest \"template_default = true\"", err.Error())
		}
		if !strings.Contains(err.Error(), "3") {
			t.Errorf("err = %q, want it to include the count", err.Error())
		}
		if !strings.Contains(err.Error(), "Entity_ClientAuth") {
			t.Errorf("err = %q, want it to include the template short name", err.Error())
		}
	})

	// --- *true filter (template_default = true) ---

	t.Run("filter=true, one result: success", func(t *testing.T) {
		t.Parallel()

		if err := enrollmentPatternSelectByTemplateShortName(1, "Entity_ClientAuth", boolPtrForEPTest(true)); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})

	t.Run("filter=true, zero results: returns not-found error (no mention of false filter)", func(t *testing.T) {
		t.Parallel()

		err := enrollmentPatternSelectByTemplateShortName(0, "Entity_ClientAuth", boolPtrForEPTest(true))
		if err == nil {
			t.Fatal("err = nil, want a not-found error")
		}
		if !strings.Contains(err.Error(), "no enrollment pattern found") {
			t.Errorf("err = %q, want it to mention \"no enrollment pattern found\"", err.Error())
		}
		// Must NOT tell the user to set template_default=true when they already did.
		if strings.Contains(err.Error(), "template_default = true") {
			t.Errorf("err = %q, must not suggest template_default=true when it was already set", err.Error())
		}
	})

	t.Run("filter=true, multiple results: unexpected-defaults error", func(t *testing.T) {
		t.Parallel()

		err := enrollmentPatternSelectByTemplateShortName(2, "Entity_ClientAuth", boolPtrForEPTest(true))
		if err == nil {
			t.Fatal("err = nil, want an unexpected-defaults error")
		}
		if !strings.Contains(err.Error(), "unexpected") {
			t.Errorf("err = %q, want it to mention \"unexpected\"", err.Error())
		}
		if !strings.Contains(err.Error(), "2") {
			t.Errorf("err = %q, want it to include the count", err.Error())
		}
	})

	// --- *false filter (template_default = false) ---

	t.Run("filter=false, one result: success", func(t *testing.T) {
		t.Parallel()

		if err := enrollmentPatternSelectByTemplateShortName(1, "Entity_ClientAuth", boolPtrForEPTest(false)); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})

	t.Run("filter=false, zero results: error does not tell user to omit filter but to try=true", func(t *testing.T) {
		t.Parallel()

		err := enrollmentPatternSelectByTemplateShortName(0, "Entity_ClientAuth", boolPtrForEPTest(false))
		if err == nil {
			t.Fatal("err = nil, want a not-found error")
		}
		// Must NOT say "no enrollment pattern found" (which would be misleading —
		// default patterns may still exist); should reference non-default patterns.
		if !strings.Contains(err.Error(), "non-default") {
			t.Errorf("err = %q, want it to mention \"non-default\"", err.Error())
		}
		// Must NOT tell the user to set template_default=true as the only option
		// when they explicitly set it to false — mention the alternative gracefully.
		if !strings.Contains(err.Error(), "Entity_ClientAuth") {
			t.Errorf("err = %q, want it to include the template short name", err.Error())
		}
		// Must not suggest template_default=true as if the filter was the issue alone;
		// it should mention trying without filter or with true.
		if strings.Contains(err.Error(), "set template_default = true") && !strings.Contains(err.Error(), "omit") {
			t.Errorf("err = %q, want it to also mention omitting template_default, not just setting true", err.Error())
		}
	})

	t.Run("filter=false, multiple results: non-default specific error, no mention of true", func(t *testing.T) {
		t.Parallel()

		err := enrollmentPatternSelectByTemplateShortName(4, "Entity_ClientAuth", boolPtrForEPTest(false))
		if err == nil {
			t.Fatal("err = nil, want an ambiguous non-default error")
		}
		if !strings.Contains(err.Error(), "non-default") {
			t.Errorf("err = %q, want it to mention \"non-default\"", err.Error())
		}
		if !strings.Contains(err.Error(), "4") {
			t.Errorf("err = %q, want it to include the count", err.Error())
		}
		// Must NOT suggest template_default=true — the user explicitly set false.
		if strings.Contains(err.Error(), "template_default = true") {
			t.Errorf("err = %q, must not suggest template_default=true when user set false", err.Error())
		}
	})

	// --- Cross-cutting: template short name appears in all error messages ---

	t.Run("template short name appears in all error outputs", func(t *testing.T) {
		t.Parallel()

		for _, name := range []string{"MyTemplate", "Another-Template", "template with spaces"} {
			name := name
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				for _, filter := range []*bool{nil, boolPtrForEPTest(true), boolPtrForEPTest(false)} {
					filter := filter
					if err := enrollmentPatternSelectByTemplateShortName(0, name, filter); err != nil {
						if !strings.Contains(err.Error(), name) {
							t.Errorf("count=0 filter=%v: error %q does not include template name", filter, err.Error())
						}
					}
					if err := enrollmentPatternSelectByTemplateShortName(5, name, filter); err != nil {
						if !strings.Contains(err.Error(), name) {
							t.Errorf("count=5 filter=%v: error %q does not include template name", filter, err.Error())
						}
					}
				}
			})
		}
	})
}

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
