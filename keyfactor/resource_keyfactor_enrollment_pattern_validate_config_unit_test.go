package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests -- PR #210 full-review round 2 findings F3/F4:
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

	t.Run("restrict_cas=true with no certificate_authority_ids is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			RestrictCAs:             types.Bool{Value: true},
			CertificateAuthorityIds: types.List{Null: true, ElemType: types.Int64Type},
			UseADPermissions:        noUseADPermissionsCheck,
			AssociatedRoleNames:     noAssociatedRoleNamesCheck,
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if !hasAttributeError(diags, "Missing certificate authorities for restrict_cas") {
			t.Errorf("diags = %+v, want an error for restrict_cas=true with no certificate_authority_ids", diags)
		}
	})

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

	t.Run("use_ad_permissions=false with no associated_role_names is an error", func(t *testing.T) {
		t.Parallel()
		cfg := KeyfactorEnrollmentPatternState{
			UseADPermissions:    types.Bool{Value: false},
			AssociatedRoleNames: types.List{Null: true, ElemType: types.StringType},
		}
		diags := validateEnrollmentPatternConfigConstraints(cfg)
		if !hasAttributeError(diags, "Missing associated roles for use_ad_permissions = false") {
			t.Errorf(
				"diags = %+v, want an error for use_ad_permissions=false with no associated_role_names", diags,
			)
		}
	})

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
