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
// Regression tests -- PR #210 full-review round 2 findings F3/F4, and
// full-review finding F5:
//
// restrict_cas's schema description states "If true, at least one CA must
// be configured" and use_ad_permissions's schema description states "If
// false, at least one value must be provided for associated_role_names" --
// but until validateEnrollmentPatternConfigConstraints (called from
// resourceEnrollmentPattern.ValidateConfig) was added, nothing actually
// enforced either constraint. A config declaring restrict_cas = true with no
// certificate_authority_ids (or use_ad_permissions = false with no
// associated_role_names) would silently apply -- Command may or may not
// reject it, but the provider itself gave no config-time feedback despite
// documenting the requirement.
//
// F5: the ORIGINAL version of this check treated a Null (undeclared)
// certificate_authority_ids/associated_role_names identically to a KNOWN,
// explicitly-empty one -- contradicting this same function's own doc
// comment ("A null/unknown value ... is never an error"). That broke the
// ordinary import-then-manage flow: GetById never echoes either field back
// (see KeyfactorEnrollmentPatternState's doc comment), so an imported
// pattern's certificate_authority_ids/associated_role_names always starts
// Null in state, and a config that re-declares restrict_cas=true/
// use_ad_permissions=false while leaving the corresponding list undeclared
// -- exactly the path Update()'s prior-state fallback exists to support --
// hard-errored even though CAs/roles genuinely exist server-side. Several
// sub-tests below were themselves updated to assert the corrected (fixed)
// behavior; see each one's comment for what it asserted before the fix.
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
	// (Null: false, Value: false) would spuriously trip the unrelated F4
	// use_ad_permissions=false check these RestrictCAs-focused cases don't
	// intend to exercise.
	noUseADPermissionsCheck := types.Bool{Null: true}
	noAssociatedRoleNamesCheck := types.List{Null: true, ElemType: types.StringType}

	// full-review finding F5: a Null (undeclared) certificate_authority_ids
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
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			UseADPermissions:        noUseADPermissionsCheck,
			AssociatedRoleNames:     noAssociatedRoleNamesCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Missing certificate authorities for restrict_cas") {
			t.Errorf(
				"diags = %+v, want no error for restrict_cas=true with certificate_authority_ids undeclared "+
					"(null) -- null means \"undeclared,\" not \"empty\"; only a known, explicitly-empty list "+
					"should error (see F5)", diags,
			)
		}
	})

	// Unlike the Null case above, a KNOWN, explicitly-empty list genuinely
	// means "zero CAs configured" -- this is the real error case F5
	// preserves.
	t.Run("restrict_cas=true with an explicitly empty certificate_authority_ids is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs:             types.Bool{Value: true},
			CertificateAuthorityIds: types.List{ElemType: types.Int64Type, Elems: []attr.Value{}},
			UseADPermissions:        noUseADPermissionsCheck,
			AssociatedRoleNames:     noAssociatedRoleNamesCheck,
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
			CertificateAuthorityIds: types.List{
				ElemType: types.Int64Type,
				Elems:    []attr.Value{types.Int64{Value: 1}},
			},
			UseADPermissions:    noUseADPermissionsCheck,
			AssociatedRoleNames: noAssociatedRoleNamesCheck,
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
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			UseADPermissions:        noUseADPermissionsCheck,
			AssociatedRoleNames:     noAssociatedRoleNamesCheck,
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
			CertificateAuthorityIds: types.List{
				ElemType: types.Int64Type,
				Elems:    []attr.Value{types.Int64{Value: 1}},
			},
			UseADPermissions:    noUseADPermissionsCheck,
			AssociatedRoleNames: noAssociatedRoleNamesCheck,
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
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			UseADPermissions:        noUseADPermissionsCheck,
			AssociatedRoleNames:     noAssociatedRoleNamesCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if len(diags) != 0 {
			t.Errorf("diags = %+v, want no diagnostics", diags)
		}
	})
}

func TestUnitValidateEnrollmentPatternConfigConstraints_UseADPermissions(t *testing.T) {
	t.Parallel()

	// full-review finding F5: a Null (undeclared) associated_role_names
	// must NOT be a config error -- see the identical
	// certificate_authority_ids/restrict_cas rationale above. This is the
	// import-then-manage flow: an imported pattern's associated_role_names
	// starts Null in state, and re-declaring use_ad_permissions = false
	// while leaving associated_role_names undeclared -- relying on
	// Update()'s prior-state fallback to preserve existing membership --
	// must NOT hard-error just because it's undeclared. Before the fix,
	// this sub-test asserted the OPPOSITE (an error) -- i.e. it encoded
	// the bug itself.
	t.Run("use_ad_permissions=false with no associated_role_names (undeclared/null) is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			UseADPermissions:    types.Bool{Value: false},
			AssociatedRoleNames: types.List{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if hasAttributeError(diags, "Missing associated roles for use_ad_permissions = false") {
			t.Errorf(
				"diags = %+v, want no error for use_ad_permissions=false with associated_role_names "+
					"undeclared (null) -- null means \"undeclared,\" not \"empty\"; only a known, "+
					"explicitly-empty list should error (see F5)", diags,
			)
		}
	})

	// Unlike the Null case above, a KNOWN, explicitly-empty list genuinely
	// means "zero roles configured" -- this is the real error case F5
	// preserves.
	t.Run("use_ad_permissions=false with an explicitly empty associated_role_names is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			UseADPermissions:    types.Bool{Value: false},
			AssociatedRoleNames: types.List{ElemType: types.StringType, Elems: nil},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if !hasAttributeError(diags, "Missing associated roles for use_ad_permissions = false") {
			t.Errorf(
				"diags = %+v, want an error for use_ad_permissions=false with associated_role_names = []", diags,
			)
		}
	})

	t.Run("use_ad_permissions=false with a non-empty associated_role_names is not an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			UseADPermissions: types.Bool{Value: false},
			AssociatedRoleNames: types.List{
				ElemType: types.StringType,
				Elems:    []attr.Value{types.String{Value: "Administrator"}},
			},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if diags.HasError() {
			t.Errorf("diags = %+v, want no error when associated_role_names is non-empty", diags)
		}
	})

	t.Run("use_ad_permissions=true with no associated_role_names is clean", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			UseADPermissions:    types.Bool{Value: true},
			AssociatedRoleNames: types.List{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if len(diags) != 0 {
			t.Errorf("diags = %+v, want no diagnostics", diags)
		}
	})

	t.Run("use_ad_permissions unknown is never an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			UseADPermissions:    types.Bool{Unknown: true},
			AssociatedRoleNames: types.List{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if len(diags) != 0 {
			t.Errorf("diags = %+v, want no diagnostics when use_ad_permissions is Unknown", diags)
		}
	})
}

// TestUnitEnrollmentPatternValidateConfig_ImportThenManageDoesNotError is the
// full-review finding F5 end-to-end regression test: drives the actual
// resourceEnrollmentPattern.ValidateConfig method (not just the factored-out
// validateEnrollmentPatternConfigConstraints helper) against a Config shape
// matching exactly what a user would write immediately after `terraform
// import` -- restrict_cas=true and use_ad_permissions=false re-declared
// (matching the server's current settings), but certificate_authority_ids
// and associated_role_names left undeclared, because GetById/ImportState
// never echo either field back (see KeyfactorEnrollmentPatternState's doc
// comment) and the user has no other way to learn their current values from
// Terraform's own state to re-declare them. Before the fix, this exact,
// ordinary post-import config hard-errored on both fields simultaneously.
func TestUnitEnrollmentPatternValidateConfig_ImportThenManageDoesNotError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	schema := enrollmentPatternSchemaForTest(t, ctx)

	cfg := blankEnrollmentPatternState()
	cfg.Name = types.String{Value: "Imported Pattern"}
	cfg.TemplateId = types.Int64{Value: 1}
	cfg.RestrictCAs = types.Bool{Value: true}
	cfg.UseADPermissions = types.Bool{Value: false}
	// certificate_authority_ids / associated_role_names deliberately left
	// at blankEnrollmentPatternState's Null default -- exactly what a
	// post-import config looks like.

	config := asEnrollmentPatternConfig(t, ctx, schema, cfg)

	r := resourceEnrollmentPattern{}
	request := tfsdk.ValidateResourceConfigRequest{Config: config}
	response := &tfsdk.ValidateResourceConfigResponse{}
	r.ValidateConfig(ctx, request, response)

	if hasAttributeError(response.Diagnostics, "Missing certificate authorities for restrict_cas") {
		t.Errorf(
			"diags = %+v, want no error for restrict_cas=true with certificate_authority_ids undeclared "+
				"(the post-import shape) -- see F5", response.Diagnostics,
		)
	}
	if hasAttributeError(response.Diagnostics, "Missing associated roles for use_ad_permissions = false") {
		t.Errorf(
			"diags = %+v, want no error for use_ad_permissions=false with associated_role_names undeclared "+
				"(the post-import shape) -- see F5", response.Diagnostics,
		)
	}
}
