package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- PR #210 full-review finding FIX-2:
//
// query is certificate_collection's defining attribute -- a certificate
// collection IS its query -- but Command's GetById never returns it (see
// KeyfactorCertificateCollectionState's doc comment), so the provider has no
// server-side value to fall back on if a user removes `query` from
// configuration on a later apply. Before validateCertificateCollectionConfig
// Constraints existed, query was Optional-only (no Computed) with a dead
// UseStateForUnknown plan modifier, and Update() silently resent the prior
// state's non-null query when config left it undeclared -- producing a
// genuine "provider produced inconsistent result after apply" (plan: null,
// final state: the resent non-null value). Requiring query to always be
// declared and non-empty at config-validation time closes that gap before
// plan/apply ever runs.
// ---------------------------------------------------------------------------

func TestUnitValidateCertificateCollectionConfigConstraints(t *testing.T) {
	t.Parallel()

	t.Run("undeclared (null) query is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorCertificateCollectionState{
			Query: types.String{Null: true},
		}
		diags := validateCertificateCollectionConfigConstraints(cfg)
		if !hasAttributeError(diags, "Missing certificate collection query") {
			t.Errorf("diags = %+v, want an error for an undeclared query", diags)
		}
	})

	t.Run("explicitly empty-string query is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorCertificateCollectionState{
			Query: types.String{Value: ""},
		}
		diags := validateCertificateCollectionConfigConstraints(cfg)
		if !hasAttributeError(diags, "Missing certificate collection query") {
			t.Errorf("diags = %+v, want an error for an empty-string query", diags)
		}
	})

	t.Run("non-empty query is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorCertificateCollectionState{
			Query: types.String{Value: `IssuedDN -contains "demo"`},
		}
		diags := validateCertificateCollectionConfigConstraints(cfg)
		if diags.HasError() {
			t.Errorf("diags = %+v, want no error for a non-empty query", diags)
		}
	})

	t.Run("unknown query is never an error (config-time value not yet resolvable)", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorCertificateCollectionState{
			Query: types.String{Unknown: true},
		}
		diags := validateCertificateCollectionConfigConstraints(cfg)
		if len(diags) != 0 {
			t.Errorf("diags = %+v, want no diagnostics when query is Unknown", diags)
		}
	})
}
