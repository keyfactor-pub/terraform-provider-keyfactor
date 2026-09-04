package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- full-review finding F7 (verified live against
// kfclab):
//
// Command's EnrollmentPatterns Create/Update/GetById responses echo an
// explicit `"Options": []` for EVERY enrollment field entry, including ones
// whose `options` was never declared in config at all -- NOT only ones that
// genuinely declared `options = []`, as enrollmentPatternFieldsToState's
// original doc comment assumed. options is Optional-only (no Computed, no
// plan modifier), so its planned value for a given entry is always exactly
// that entry's declared config value: Null if undeclared. Writing the
// server's non-null-empty echo straight into the final state for an
// undeclared entry disagrees with the Null the plan promised -- "Provider
// produced inconsistent result after apply" -- on this resource's ordinary
// Update() path (verified live: probing POST /EnrollmentPatterns against
// kfclab with an enrollment field declaring no options returned
// `"Options": []` in the response, not null or an omitted key).
//
// reconcileEnrollmentFieldsOptionsFromPlan collapses that server-echoed []
// back to Null wherever the corresponding plan/config (or, for Read(),
// prior state) entry declared options as Null, while leaving a genuinely
// non-null (even empty) plan value untouched.
// ---------------------------------------------------------------------------

func TestUnitReconcileEnrollmentFieldsOptionsFromPlan(t *testing.T) {
	t.Parallel()

	nullOpts := types.List{Null: true, ElemType: types.StringType}
	emptyOpts := types.List{ElemType: types.StringType, Elems: []attr.Value{}}
	populatedOpts := types.List{ElemType: types.StringType, Elems: []attr.Value{types.String{Value: "a"}}}

	field := func(name string, options types.List) EnrollmentPatternResourceField {
		return EnrollmentPatternResourceField{
			Name:     types.String{Value: name},
			DataType: types.Int64{Value: 1},
			Options:  options,
		}
	}

	t.Run("undeclared options (plan null) collapses server-echoed empty list to null", func(t *testing.T) {
		t.Parallel()
		plan := []EnrollmentPatternResourceField{field("f1", nullOpts)}
		// Server always echoes "Options": [] for an undeclared entry --
		// verified live against kfclab.
		response := []EnrollmentPatternResourceField{field("f1", emptyOpts)}

		got := reconcileEnrollmentFieldsOptionsFromPlan(plan, response)
		if !got[0].Options.Null {
			t.Errorf("Options = %+v, want Null (plan declared options undeclared)", got[0].Options)
		}
	})

	t.Run("genuinely-declared empty options (plan non-null-empty) is left untouched", func(t *testing.T) {
		t.Parallel()
		plan := []EnrollmentPatternResourceField{field("f1", emptyOpts)}
		response := []EnrollmentPatternResourceField{field("f1", emptyOpts)}

		got := reconcileEnrollmentFieldsOptionsFromPlan(plan, response)
		if got[0].Options.Null {
			t.Errorf("Options = %+v, want the known non-null empty list preserved (plan genuinely declared options = [])", got[0].Options)
		}
	})

	t.Run("populated options is left untouched", func(t *testing.T) {
		t.Parallel()
		plan := []EnrollmentPatternResourceField{field("f1", populatedOpts)}
		response := []EnrollmentPatternResourceField{field("f1", populatedOpts)}

		got := reconcileEnrollmentFieldsOptionsFromPlan(plan, response)
		if got[0].Options.Null || len(got[0].Options.Elems) != 1 {
			t.Errorf("Options = %+v, want the populated list preserved", got[0].Options)
		}
	})

	t.Run("multiple entries reconciled independently by index", func(t *testing.T) {
		t.Parallel()
		plan := []EnrollmentPatternResourceField{
			field("undeclared", nullOpts),
			field("declared-empty", emptyOpts),
			field("populated", populatedOpts),
		}
		response := []EnrollmentPatternResourceField{
			field("undeclared", emptyOpts),
			field("declared-empty", emptyOpts),
			field("populated", populatedOpts),
		}

		got := reconcileEnrollmentFieldsOptionsFromPlan(plan, response)
		if !got[0].Options.Null {
			t.Errorf("entry 0 (undeclared): Options = %+v, want Null", got[0].Options)
		}
		if got[1].Options.Null {
			t.Errorf("entry 1 (declared-empty): Options = %+v, want non-null empty preserved", got[1].Options)
		}
		if got[2].Options.Null || len(got[2].Options.Elems) != 1 {
			t.Errorf("entry 2 (populated): Options = %+v, want populated preserved", got[2].Options)
		}
	})

	t.Run("mismatched lengths reconcile only up to the shorter length", func(t *testing.T) {
		t.Parallel()
		plan := []EnrollmentPatternResourceField{field("f1", nullOpts)}
		response := []EnrollmentPatternResourceField{field("f1", emptyOpts), field("f2", emptyOpts)}

		got := reconcileEnrollmentFieldsOptionsFromPlan(plan, response)
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2 (defensive: extra response entries preserved)", len(got))
		}
		if !got[0].Options.Null {
			t.Errorf("entry 0: Options = %+v, want Null", got[0].Options)
		}
		if got[1].Options.Null {
			t.Errorf("entry 1 (no matching plan entry): Options = %+v, want left untouched", got[1].Options)
		}
	})

	t.Run("nil plan is a no-op (defensive; callers gate on plan != nil before calling)", func(t *testing.T) {
		t.Parallel()
		response := []EnrollmentPatternResourceField{field("f1", emptyOpts)}
		got := reconcileEnrollmentFieldsOptionsFromPlan(nil, response)
		if got[0].Options.Null {
			t.Errorf("Options = %+v, want left untouched when plan is nil", got[0].Options)
		}
	})
}
