package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
)

// ---------------------------------------------------------------------------
// Regression test — full-review round 1 finding #2 (correctness, high),
// extended for the Weekly schedule variant:
//
// All twelve schedule attributes (full_scan/incremental_scan/threshold_check
// x interval/daily/weekly_days/weekly_time) must be wired to
// pairedVariantModifier (attribute_contract.go), not a bare
// tfsdk.UseStateForUnknown(), so that switching between an Interval, Daily,
// or Weekly schedule in one apply nulls the sibling variant(s) at plan time
// instead of resurrecting a stale value from state -- see
// attribute_contract_test.go for pairedVariantModifier's own behavioral
// regression tests (declared value untouched, sibling declared plans null,
// neither declared copies state, Create stays Unknown, sibling Unknown
// treated as declared, and the three-way group variants exercising exactly
// this Interval/Daily/Weekly shape).
//
// This file's own test is schema-level: it confirms every one of the twelve
// schedule attributes is actually wired to pairedVariantModifier, naming the
// correct sibling attribute(s), rather than asserting the modifier's
// behavior is a bare tfsdk.UseStateForUnknown() (or, for a mid-migration
// bug, wired to the wrong modifier instance/sibling entirely) -- a
// schema-definition typo here would silently disable the fix for one
// attribute while every other reconciliation is covered.
// ---------------------------------------------------------------------------

// TestUnitCAScheduleAttributesUsePairedVariantModifier is the schema-level
// regression test: all twelve schedule attributes must be wired to
// pairedVariantModifier, naming every OTHER variant's attribute(s) as
// siblings (never its own co-attribute, e.g. full_scan_weekly_days must not
// list full_scan_weekly_time as a sibling -- the two are co-required, not
// mutually exclusive, with each other).
func TestUnitCAScheduleAttributesUsePairedVariantModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := caSchema(t, ctx)

	cases := []struct {
		attrName string
		siblings []string
	}{
		{"full_scan_interval_minutes", []string{"full_scan_daily_time", "full_scan_weekly_days", "full_scan_weekly_time"}},
		{"full_scan_daily_time", []string{"full_scan_interval_minutes", "full_scan_weekly_days", "full_scan_weekly_time"}},
		{"full_scan_weekly_days", []string{"full_scan_interval_minutes", "full_scan_daily_time"}},
		{"full_scan_weekly_time", []string{"full_scan_interval_minutes", "full_scan_daily_time"}},
		{"incremental_scan_interval_minutes", []string{"incremental_scan_daily_time", "incremental_scan_weekly_days", "incremental_scan_weekly_time"}},
		{"incremental_scan_daily_time", []string{"incremental_scan_interval_minutes", "incremental_scan_weekly_days", "incremental_scan_weekly_time"}},
		{"incremental_scan_weekly_days", []string{"incremental_scan_interval_minutes", "incremental_scan_daily_time"}},
		{"incremental_scan_weekly_time", []string{"incremental_scan_interval_minutes", "incremental_scan_daily_time"}},
		{"threshold_check_interval_minutes", []string{"threshold_check_daily_time", "threshold_check_weekly_days", "threshold_check_weekly_time"}},
		{"threshold_check_daily_time", []string{"threshold_check_interval_minutes", "threshold_check_weekly_days", "threshold_check_weekly_time"}},
		{"threshold_check_weekly_days", []string{"threshold_check_interval_minutes", "threshold_check_daily_time"}},
		{"threshold_check_weekly_time", []string{"threshold_check_interval_minutes", "threshold_check_daily_time"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.attrName, func(t *testing.T) {
			t.Parallel()
			schemaAttr, ok := schema.Attributes[tc.attrName]
			if !ok {
				t.Fatalf("schema has no %s attribute", tc.attrName)
			}
			if len(schemaAttr.PlanModifiers) != 1 {
				t.Fatalf("%s: want exactly 1 plan modifier, got %d", tc.attrName, len(schemaAttr.PlanModifiers))
			}
			m, ok := schemaAttr.PlanModifiers[0].(pairedVariantModifier)
			if !ok {
				t.Fatalf(
					"%s: plan modifier is %T, want pairedVariantModifier -- a bare tfsdk.UseStateForUnknown() "+
						"here reproduces finding #2: switching schedule variants would resurrect the stale "+
						"sibling value onto the plan, failing apply with \"Provider produced inconsistent "+
						"result after apply\"", tc.attrName, schemaAttr.PlanModifiers[0],
				)
			}
			if len(m.siblings) != len(tc.siblings) {
				t.Fatalf("%s: siblings = %v, want %v", tc.attrName, m.siblings, tc.siblings)
			}
			for i, want := range tc.siblings {
				if m.siblings[i] != want {
					t.Errorf("%s: siblings[%d] = %q, want %q", tc.attrName, i, m.siblings[i], want)
				}
			}
			// Sanity: an attribute must never list itself as its own sibling.
			for _, s := range m.siblings {
				if s == tc.attrName {
					t.Errorf("%s: siblings list includes itself (%q) -- an attribute cannot be mutually exclusive with itself", tc.attrName, s)
				}
				_ = path.Root(s) // siblings are schema attribute names, not paths, but confirm they're valid path segments
			}
		})
	}
}
