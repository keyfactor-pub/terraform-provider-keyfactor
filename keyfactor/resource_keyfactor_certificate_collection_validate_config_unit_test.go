package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: query must always be declared and non-empty.
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
//
// query is now schema'd as Required (not
// Optional). ValidateConfig/validateCertificateCollectionConfigConstraints
// is retained only for the non-empty check the schema itself cannot
// express ("must be declared" is now Required's job, not a runtime
// check's) -- the "undeclared (null) query" sub-test below is kept as a
// defensive/documentation case even though Required now makes it
// unreachable through normal `terraform apply` (Core rejects an omitted
// Required attribute before ValidateConfig ever runs).
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

// TestUnitCertificateCollectionQueryIsRequired is the schema-level
// regression test: query is now Required
// (not Optional), so the schema itself -- not just a runtime
// ValidateConfig check -- rejects an omitted query, and `terraform
// validate` catches it before ValidateConfig ever runs.
func TestUnitCertificateCollectionQueryIsRequired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema, diags := resourceCertificateCollectionType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("test setup: GetSchema returned diagnostics: %+v", diags)
	}

	attr, ok := schema.Attributes["query"]
	if !ok {
		t.Fatal("schema has no query attribute")
	}
	if !attr.Required {
		t.Error(
			"query: expected Required=true -- F10 makes the schema itself express \"must always be " +
				"declared\" instead of relying solely on a runtime ValidateConfig check",
		)
	}
	if attr.Optional {
		t.Error("query: expected Optional=false now that it is Required")
	}
	if attr.Computed {
		t.Error("query: expected Computed=false -- it remains write-only, not server-derived")
	}
}
