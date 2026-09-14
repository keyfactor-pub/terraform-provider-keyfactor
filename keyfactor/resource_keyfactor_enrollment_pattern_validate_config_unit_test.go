package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests: restrict_cas config-time enforcement.
//
// restrict_cas's schema description states "If true, at least one CA must
// be configured" -- but until validateEnrollmentPatternConfigConstraints
// (called from resourceEnrollmentPattern.ValidateConfig) was added, nothing
// actually enforced this constraint. A config declaring restrict_cas = true
// with no certificate_authority_ids would silently apply -- Command may or
// may not reject it, but the provider gave no config-time feedback.
//
// The ORIGINAL version of this check treated a Null (undeclared)
// certificate_authority_ids identically to a KNOWN, explicitly-empty one --
// contradicting this same function's own doc comment ("A null/unknown value
// ... is never an error"). That broke the ordinary import-then-manage flow:
// GetById never echoes certificate_authority_ids back (see
// KeyfactorEnrollmentPatternState's doc comment), so an imported pattern's
// certificate_authority_ids always starts Null in state, and a config that
// re-declares restrict_cas=true while leaving certificate_authority_ids
// undeclared -- relying on Update()'s prior-state fallback -- hard-errored.
// Several sub-tests below were updated to assert the corrected behavior; see
// each one's comment for what it asserted before the fix.
// ---------------------------------------------------------------------------

func hasAttributeError(diags diag.Diagnostics, summary string) bool {
	for _, d := range diags {
		if d.Severity() == diag.SeverityError && d.Summary() == summary {
			return true
		}
	}
	return false
}

func hasAttributeWarning(diags diag.Diagnostics, summary string) bool {
	for _, d := range diags {
		if d.Severity() == diag.SeverityWarning && d.Summary() == summary {
			return true
		}
	}
	return false
}

func TestUnitValidateEnrollmentPatternConfigConstraints_RestrictCAs(t *testing.T) {
	t.Parallel()

	// UseADPermissions is left Null (Unknown: false, Null: true) in every
	// case below via this shared default -- otherwise its Go zero value
	// (Null: false, Value: false) is a known false which differs from the
	// undeclared case these RestrictCAs-focused tests don't intend to probe.
	noUseADPermissionsCheck := types.Bool{Null: true}

	// A Null (undeclared) certificate_authority_ids
	// must NOT be a config error -- only a KNOWN, explicitly-empty list is
	// (see the next sub-test). This is exactly the import-then-manage flow:
	// GetById never echoes certificate_authority_ids back (see
	// KeyfactorEnrollmentPatternState's doc comment), so an imported
	// pattern's certificate_authority_ids starts Null in state, and a
	// config that re-declares restrict_cas = true while leaving
	// certificate_authority_ids undeclared -- relying on Update()'s
	// prior-state fallback to preserve the existing, server-side CA
	// restriction -- must NOT hard-error just because it's undeclared.
	// Before the fix, this sub-test asserted the OPPOSITE (an error) --
	// i.e. it encoded the bug itself.
	t.Run("restrict_cas=true with no certificate_authority_ids (undeclared/null) is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs:             types.Bool{Value: true},
			CertificateAuthorityIds: types.Set{Null: true, ElemType: types.Int64Type},
			UseADPermissions:        noUseADPermissionsCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Missing certificate authorities for restrict_cas") {
			t.Errorf(
				"diags = %+v, want no error for restrict_cas=true with certificate_authority_ids undeclared "+
					"(null) -- null means \"undeclared,\" not \"empty\"; only a known, explicitly-empty list "+
					"should error", diags,
			)
		}
	})

	// Unlike the Null case above, a KNOWN, explicitly-empty list genuinely
	// means "zero CAs configured" -- this is the real error case the fix
	// preserves.
	t.Run("restrict_cas=true with an explicitly empty certificate_authority_ids is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs:             types.Bool{Value: true},
			CertificateAuthorityIds: types.Set{ElemType: types.Int64Type, Elems: []attr.Value{}},
			UseADPermissions:        noUseADPermissionsCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if !hasAttributeError(diags, "Missing certificate authorities for restrict_cas") {
			t.Errorf("diags = %+v, want an error for restrict_cas=true with certificate_authority_ids = []", diags)
		}
	})

	t.Run("restrict_cas=true with a non-empty certificate_authority_ids is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs: types.Bool{Value: true},
			CertificateAuthorityIds: types.Set{
				ElemType: types.Int64Type,
				Elems:    []attr.Value{types.Int64{Value: 1}},
			},
			UseADPermissions: noUseADPermissionsCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Missing certificate authorities for restrict_cas") {
			t.Errorf("diags = %+v, want no error when certificate_authority_ids is non-empty", diags)
		}
	})

	t.Run("restrict_cas unknown is never an error (config-time value not yet resolvable)", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs:             types.Bool{Unknown: true},
			CertificateAuthorityIds: types.Set{Null: true, ElemType: types.Int64Type},
			UseADPermissions:        noUseADPermissionsCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if len(diags) != 0 {
			t.Errorf("diags = %+v, want no diagnostics when restrict_cas is Unknown", diags)
		}
	})

	t.Run("restrict_cas=false with a non-empty certificate_authority_ids is a warning, not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs: types.Bool{Value: false},
			CertificateAuthorityIds: types.Set{
				ElemType: types.Int64Type,
				Elems:    []attr.Value{types.Int64{Value: 1}},
			},
			UseADPermissions: noUseADPermissionsCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if diags.HasError() {
			t.Errorf("diags = %+v, want no error (this combination is a soft/unproven no-op, not a hard failure)", diags)
		}
		if !hasAttributeWarning(diags, "certificate_authority_ids has no effect") {
			t.Errorf("diags = %+v, want a warning flagging the likely-inert certificate_authority_ids", diags)
		}
	})

	t.Run("restrict_cas=false with no certificate_authority_ids is clean", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs:             types.Bool{Value: false},
			CertificateAuthorityIds: types.Set{Null: true, ElemType: types.Int64Type},
			UseADPermissions:        noUseADPermissionsCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if len(diags) != 0 {
			t.Errorf("diags = %+v, want no diagnostics", diags)
		}
	})
}

// TestUnitEnrollmentPatternValidateConfig_ImportThenManageDoesNotError is the
// end-to-end regression test: drives the actual
// resourceEnrollmentPattern.ValidateConfig method (not just the factored-out
// validateEnrollmentPatternConfigConstraints helper) against a Config shape
// matching exactly what a user would write immediately after `terraform
// import` -- restrict_cas=true re-declared (matching the server's current
// setting), but certificate_authority_ids left undeclared, because
// GetById/ImportState never echoes it back (see KeyfactorEnrollmentPatternState's
// doc comment). Before the fix, this exact ordinary post-import config
// hard-errored on restrict_cas.
func TestUnitEnrollmentPatternValidateConfig_ImportThenManageDoesNotError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	cfg := blankEnrollmentPatternState()
	cfg.Name = types.String{Value: "Imported Pattern"}
	cfg.TemplateId = types.Int64{Value: 1}
	cfg.RestrictCAs = types.Bool{Value: true}
	cfg.UseADPermissions = types.Bool{Value: false}
	// certificate_authority_ids deliberately left at blankEnrollmentPatternState's
	// Null default -- exactly what a post-import config looks like.

	config := asEnrollmentPatternConfig(t, ctx, schema, cfg)

	r := resourceEnrollmentPattern{}
	request := tfsdk.ValidateResourceConfigRequest{Config: config}
	response := &tfsdk.ValidateResourceConfigResponse{}
	r.ValidateConfig(ctx, request, response)

	if hasAttributeError(response.Diagnostics, "Missing certificate authorities for restrict_cas") {
		t.Errorf(
			"diags = %+v, want no error for restrict_cas=true with certificate_authority_ids undeclared "+
				"(the post-import shape)", response.Diagnostics,
		)
	}
}
