package keyfactor

import (
	"context"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Auth certificate metadata else-null branch
// ---------------------------------------------------------------------------

// TestUnitCAReadAuthCertificateMetadataNullWhenAbsent is the red/green
// regression test: caResponseToState only set
// auth_certificate_issued_dn/auth_certificate_issuer_dn/
// auth_certificate_thumbprint inside "if resp.AuthCertificate != nil", so a
// CA with no auth certificate configured left those three fields at the Go
// zero-value types.String{} -- a KNOWN empty string, not Null -- instead of
// explicit Null like every other pointer field in this function
// (boolPtrToTfBool/nullableStringToTfString/etc. all return Null on a nil
// pointer). Before the fix, the assertions below fail because
// newState.AuthCertificateIssuedDN.Null is false (Value == "").
func TestUnitCAReadAuthCertificateMetadataNullWhenAbsent(t *testing.T) {
	resp := &v1.CertificateAuthoritiesCertificateAuthorityResponse{}
	resp.SetId(47)
	resp.SetLogicalName("tf-unit-ca-no-auth-cert")
	resp.SetHostName("ca.lab.example.com")
	caType := v1.CSSCMSCoreEnumsCertificateAuthorityType(1)
	resp.CAType = &caType
	// resp.AuthCertificate intentionally left nil: no auth certificate configured.

	newState := caResponseToState(resp)

	assert.True(t, newState.AuthCertificateIssuedDN.Null,
		"auth_certificate_issued_dn must be Null (not a known empty string) when the CA has no auth certificate")
	assert.True(t, newState.AuthCertificateIssuerDN.Null,
		"auth_certificate_issuer_dn must be Null (not a known empty string) when the CA has no auth certificate")
	assert.True(t, newState.AuthCertificateThumbprint.Null,
		"auth_certificate_thumbprint must be Null (not a known empty string) when the CA has no auth certificate")
}

// ---------------------------------------------------------------------------
// Properties JSON-normalization plan modifier
// ---------------------------------------------------------------------------

// TestUnitCANormalizePropertiesJSON verifies the helper (previously dead
// code, never wired into a plan modifier) treats differently-formatted but
// semantically-equal JSON as equal, and falls back to the raw string for
// unparseable input.
func TestUnitCANormalizePropertiesJSON(t *testing.T) {
	assert.Equal(t,
		normalizePropertiesJSON(`{"a":1,"b":2}`),
		normalizePropertiesJSON(`{"b": 2, "a": 1}`),
		"key order and whitespace must not affect the normalized form",
	)
	assert.Equal(t, "", normalizePropertiesJSON(""), "empty string normalizes to empty string")
	assert.Equal(t, "not-json", normalizePropertiesJSON("not-json"), "unparseable input falls back to the raw string unchanged")
}

// TestUnitCAPropertiesModifierSuppressesReorderedJSONDiff is the red/green
// regression test: normalizePropertiesJSON was defined but never
// wired into a plan modifier, so with the prior schema (a bare
// tfsdk.UseStateForUnknown()) a config-declared properties value already
// plans as Known -- UseStateForUnknown only ever intervenes on an Unknown
// plan, so it does nothing here, leaving the plan at the config's literal
// text. If Command's GET re-serializes the same JSON with different key
// order/whitespace than what's in state, the plan (config text) and state
// (server's differently-formatted text) differ byte-for-byte -- a permanent
// diff even though the value is semantically unchanged. This test fails
// against the un-fixed schema (verified by temporarily swapping the
// "properties" PlanModifiers back to []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()}
// during development: resp.AttributePlan stayed at the config's text,
// `{"a":1,"b":2}` != state's `{"b":2,"a":1}`) and passes once
// normalizedJSONPropertiesModifier is wired in, since it resets the plan to
// state's exact text when the two are semantically equal.
func TestUnitCAPropertiesModifierSuppressesReorderedJSONDiff(t *testing.T) {
	state := types.String{Value: `{"b":2,"a":1}`}
	plan := types.String{Value: `{"a":1,"b":2}`} // same data, different key order -- config-declared

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  state,
		AttributeConfig: plan, // config declares the (differently-formatted) value, so config is known, not null/unknown
		AttributePlan:   plan,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	assert.False(t, resp.Diagnostics.HasError())
	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.String, got %T", resp.AttributePlan) {
		assert.Equal(t, state.Value, got.Value,
			"a plan that is semantically equal to state (differing only in JSON key order/whitespace) must be reset to state's exact text, suppressing the diff")
	}
}

// TestUnitCAPropertiesModifierSurfacesRealChange is the companion case: a
// genuinely different properties value (not just reformatted) must still
// plan as a real diff, never be suppressed by the normalization.
func TestUnitCAPropertiesModifierSurfacesRealChange(t *testing.T) {
	state := types.String{Value: `{"a":1}`}
	plan := types.String{Value: `{"a":2}`}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState: state,
		AttributePlan:  plan,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok) {
		assert.Equal(t, plan.Value, got.Value, "a genuine value change must not be suppressed")
	}
}

// TestUnitCABarePropertiesUseStateForUnknownDoesNotSuppressReorderedJSONDiff
// is the concrete "red" reproduction, run against the schema's actual
// PRE-FIX plan modifier (tfsdk.UseStateForUnknownModifier{}, what "properties"
// used before this change) rather than against a hand-edited schema: given
// the exact same config-declared-but-reordered-JSON scenario as
// TestUnitCAPropertiesModifierSuppressesReorderedJSONDiff, the bare modifier
// leaves the plan at the config's literal text because the plan is already
// Known (config declared it) -- UseStateForUnknown only ever intervenes on an
// Unknown plan. That mismatched plan-vs-state text is exactly the perpetual
// diff this bug reports. normalizedJSONPropertiesModifier (tested above)
// fixes it by resetting the plan to state's text when the two are
// semantically equal.
func TestUnitCABarePropertiesUseStateForUnknownDoesNotSuppressReorderedJSONDiff(t *testing.T) {
	state := types.String{Value: `{"b":2,"a":1}`}
	plan := types.String{Value: `{"a":1,"b":2}`} // same data, different key order -- config-declared

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  state,
		AttributeConfig: plan,
		AttributePlan:   plan,
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	tfsdk.UseStateForUnknownModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.String, got %T", resp.AttributePlan) {
		assert.NotEqual(t, state.Value, got.Value,
			"reproduces the bug: the pre-fix bare UseStateForUnknown modifier does NOT suppress a reordered-JSON diff, leaving the plan at the config's differently-formatted text")
		assert.Equal(t, plan.Value, got.Value)
	}
}

// TestUnitCAPropertiesModifierUndeclaredCopiesState covers the Computed-only
// case (properties left undeclared in config): the plan starts Unknown, and
// the modifier must copy state forward, matching plain UseStateForUnknown
// semantics.
func TestUnitCAPropertiesModifierUndeclaredCopiesState(t *testing.T) {
	state := types.String{Value: `{"a":1}`}

	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  state,
		AttributeConfig: types.String{Null: true}, // undeclared in config -- known-null, not the nil interface value
		AttributePlan:   types.String{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok) {
		assert.Equal(t, state.Value, got.Value)
		assert.False(t, got.Unknown)
	}
}

// TestUnitCAPropertiesModifierCreateStaysUnknown is the Create-time
// companion: with no prior state to copy from (AttributeState itself
// Unknown), the plan must be left Unknown rather than fabricating a value.
func TestUnitCAPropertiesModifierCreateStaysUnknown(t *testing.T) {
	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState: types.String{Unknown: true},
		AttributePlan:  types.String{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok) {
		assert.True(t, got.Unknown, "no prior state to copy from on Create -- plan must stay Unknown")
	}
}

// TestUnitCAPropertiesModifierLeavesPlanUnknownWhenConfigUnknown is the
// red/green regression test: normalizedJSONPropertiesModifier lacked the req.AttributeConfig.IsUnknown()
// guard that vendored tfsdk.UseStateForUnknownModifier has (attribute_plan_
// modification.go, comment "otherwise, interpolation gets messed up"). When
// properties is computed from a not-yet-known expression (e.g.
// jsonencode({ref = some_other_resource.attr}) where that attribute is
// unknown at plan time), the proposed plan is Unknown; without the guard,
// this modifier's "plan is Unknown -> copy state forward" branch pinned the
// plan to the stale prior-state JSON. At apply, the provider re-plans with
// the now-resolved config, and if the resolved value's normalized form
// differs from prior state, the final plan no longer matches what was
// recorded -- Terraform core then rejects the apply with "Provider produced
// inconsistent final plan". The fix mirrors the vendored modifier's own
// guard: when config is unknown, leave the plan Unknown too.
func TestUnitCAPropertiesModifierLeavesPlanUnknownWhenConfigUnknown(t *testing.T) {
	req := tfsdk.ModifyAttributePlanRequest{
		AttributeState:  types.String{Value: `{"a":1}`},
		AttributeConfig: types.String{Unknown: true}, // e.g. jsonencode(...) referencing an unknown same-run value
		AttributePlan:   types.String{Unknown: true},
	}
	resp := &tfsdk.ModifyAttributePlanResponse{AttributePlan: req.AttributePlan}

	normalizedJSONPropertiesModifier{}.Modify(context.Background(), req, resp)

	got, ok := resp.AttributePlan.(types.String)
	if assert.True(t, ok, "expected resp.AttributePlan to be types.String, got %T", resp.AttributePlan) {
		assert.True(t, got.Unknown,
			"plan must stay Unknown when config is Unknown -- pinning it to the stale prior-state value here "+
				"(the pre-fix bug) risks a later apply-time re-plan with the resolved config producing a "+
				"different final value than what was recorded, which Terraform core rejects as "+
				"\"Provider produced inconsistent final plan\"")
	}
}

// ---------------------------------------------------------------------------
// ValidateConfig constraint enforcement
// ---------------------------------------------------------------------------

// caConstraintsAllUnset has every attribute validateCAConfigConstraints
// looks at explicitly Null. A Go zero-value types.Bool{}/types.Int64{}/
// types.List{} literal is a KNOWN empty/false/zero value (Null: false), not
// Null -- left unset, EnforceUniqueDN/Standalone would spuriously look
// "declared false" and AllowedEnrollmentTypes/UseAllowedRequesters would
// spuriously look "declared 0/false", tripping the very checks these tests
// don't intend to exercise. Tests that only care about a subset of these
// attributes should copy this baseline and override just the ones under
// test.
var caConstraintsAllUnset = KeyfactorCertificateAuthority{
	EnforceUniqueDN:               types.Bool{Null: true},
	NewEndEntityOnRenewAndReissue: types.Bool{Null: true},
	CAType:                        types.Int64{Null: true},
	Standalone:                    types.Bool{Null: true},
	AllowedEnrollmentTypes:        types.Int64{Null: true},
	UseAllowedRequesters:          types.Bool{Null: true},
	AllowedRequesters:             types.List{Null: true, ElemType: types.StringType},
}

// TestUnitCAValidateConfigRejectsEnforceUniqueDNWithNewEndEntity is the
// regression test: enforce_unique_dn and new_end_entity_on_renew_and_reissue are
// documented as mutually exclusive but, before this fix, nothing enforced
// it -- both could be set to true with no plan-time error.
func TestUnitCAValidateConfigRejectsEnforceUniqueDNWithNewEndEntity(t *testing.T) {
	cfg := caConstraintsAllUnset
	cfg.EnforceUniqueDN = types.Bool{Value: true}
	cfg.NewEndEntityOnRenewAndReissue = types.Bool{Value: true}

	diags := validateCAConfigConstraints(cfg)

	assert.True(t, diags.HasError(), "enforce_unique_dn and new_end_entity_on_renew_and_reissue both true must be a plan-time error")
}

// TestUnitCAValidateConfigAllowsEnforceUniqueDNOrNewEndEntityAlone confirms
// the non-error cases for the enforce_unique_dn/new_end_entity pair: either attribute alone, or neither
// declared, must all pass cleanly.
func TestUnitCAValidateConfigAllowsEnforceUniqueDNOrNewEndEntityAlone(t *testing.T) {
	dnOnly := caConstraintsAllUnset
	dnOnly.EnforceUniqueDN = types.Bool{Value: true}
	assert.False(t, validateCAConfigConstraints(dnOnly).HasError())

	newEntityOnly := caConstraintsAllUnset
	newEntityOnly.NewEndEntityOnRenewAndReissue = types.Bool{Value: true}
	assert.False(t, validateCAConfigConstraints(newEntityOnly).HasError())

	assert.False(t, validateCAConfigConstraints(caConstraintsAllUnset).HasError())
}

// TestUnitCAValidateConfigRejectsNewEndEntityFalseForHTTPSCa is the
// regression test: new_end_entity_on_renew_and_reissue is documented as required
// true for HTTPS CAs (ca_type=1) but, before this fix, an explicit false was
// silently accepted at plan time for an HTTPS CA.
func TestUnitCAValidateConfigRejectsNewEndEntityFalseForHTTPSCa(t *testing.T) {
	cfg := caConstraintsAllUnset
	cfg.CAType = types.Int64{Value: caHTTPSType}
	cfg.NewEndEntityOnRenewAndReissue = types.Bool{Value: false}

	diags := validateCAConfigConstraints(cfg)

	assert.True(t, diags.HasError(), "new_end_entity_on_renew_and_reissue=false with ca_type=1 (HTTPS) must be a plan-time error")
}

// TestUnitCAValidateConfigAllowsNewEndEntityUnsetOrUnknownForHTTPSCa confirms
// that config-time validation never fabricates a requirement on an attribute
// the practitioner didn't declare, or on a ca_type that isn't resolvable yet
// -- only an explicitly configured, known violation is rejected.
func TestUnitCAValidateConfigAllowsNewEndEntityUnsetOrUnknownForHTTPSCa(t *testing.T) {
	undeclared := caConstraintsAllUnset
	undeclared.CAType = types.Int64{Value: caHTTPSType}
	assert.False(t, validateCAConfigConstraints(undeclared).HasError(),
		"new_end_entity_on_renew_and_reissue left undeclared must never error, even for an HTTPS CA")

	unknownCAType := caConstraintsAllUnset
	unknownCAType.CAType = types.Int64{Unknown: true}
	unknownCAType.NewEndEntityOnRenewAndReissue = types.Bool{Value: false}
	assert.False(t, validateCAConfigConstraints(unknownCAType).HasError(),
		"an unknown ca_type (e.g. referencing another resource's not-yet-known output) must never error")

	trueForHTTPS := caConstraintsAllUnset
	trueForHTTPS.CAType = types.Int64{Value: caHTTPSType}
	trueForHTTPS.NewEndEntityOnRenewAndReissue = types.Bool{Value: true}
	assert.False(t, validateCAConfigConstraints(trueForHTTPS).HasError())
}

// ---------------------------------------------------------------------------
// Regression tests: backward-compat break.
//
// An earlier version of this check relaxed the standalone-only
// check on allowed_enrollment_types/use_allowed_requesters/allowed_requesters
// from "reject on mere declaredness" to "reject only a value that actually
// conflicts" (treating 0/false/[] as no-ops). That relaxation was still
// wrong: Command's own resting/echoed value for allowed_enrollment_types on a
// REAL non-standalone HTTPS CA is 3, not 0 -- confirmed against both this
// repo's own committed terraform/certificate_authority_demo tfstate and a
// live lab CA (`GET /CertificateAuthority` against a kfclab non-standalone
// HTTPS CA returns AllowedEnrollmentTypes: 3, UseAllowedRequesters: false,
// AllowedRequesters: []). So `allowed_enrollment_types != 0` was rejecting
// the server's OWN DEFAULT for that attribute on a non-standalone CA -- every
// config produced by this project's own documented import-then-codify
// workflow (`terraform state show` output copied into config) hard-failed
// every plan after upgrading, with no deprecation path.
//
// The fix removes the standalone-only constraint entirely for all three
// attributes (see validateCAConfigConstraints's doc comment for the full
// reasoning on why use_allowed_requesters/allowed_requesters are removed
// alongside allowed_enrollment_types rather than left partially enforced) and
// relies on Command's own server-side validation instead. These tests assert
// the new behavior: none of the three attributes are ever rejected by
// ValidateConfig, regardless of their value or of standalone's value.
// ---------------------------------------------------------------------------

// TestUnitCAValidateConfigNeverRejectsAllowedEnrollmentTypesRegardlessOfStandalone
// is the direct regression test: standalone=false paired with
// allowed_enrollment_types=3 -- the exact shape Command itself returns for a
// real non-standalone HTTPS CA, and the exact shape this project's own
// certificate_authority_demo needed to drop from its config to keep working
// -- must plan cleanly. A smaller non-zero value (the old "genuine conflict"
// boundary case from an earlier, stricter version of this check) and a standalone=true pairing are also checked
// to confirm the constraint is gone, not just further relaxed.
func TestUnitCAValidateConfigNeverRejectsAllowedEnrollmentTypesRegardlessOfStandalone(t *testing.T) {
	base := func() KeyfactorCertificateAuthority {
		cfg := caConstraintsAllUnset
		cfg.Standalone = types.Bool{Value: false}
		return cfg
	}

	serverRestingValue := base()
	serverRestingValue.AllowedEnrollmentTypes = types.Int64{Value: 3}
	assert.False(t, validateCAConfigConstraints(serverRestingValue).HasError(),
		"allowed_enrollment_types=3 with standalone=false is Command's own resting value on a real non-standalone "+
			"HTTPS CA (confirmed live and via this repo's committed demo tfstate) and must not be rejected")

	smallNonZero := base()
	smallNonZero.AllowedEnrollmentTypes = types.Int64{Value: 1}
	assert.False(t, validateCAConfigConstraints(smallNonZero).HasError(),
		"allowed_enrollment_types=1 with standalone=false must not be rejected -- the standalone-only constraint "+
			"was removed entirely, not merely further relaxed")

	withStandaloneTrue := caConstraintsAllUnset
	withStandaloneTrue.Standalone = types.Bool{Value: true}
	withStandaloneTrue.AllowedEnrollmentTypes = types.Int64{Value: 2}
	assert.False(t, validateCAConfigConstraints(withStandaloneTrue).HasError())
}

// TestUnitCAValidateConfigNeverRejectsAllowedRequestersRegardlessOfStandalone
// is the companion test for use_allowed_requesters/allowed_requesters: absent
// live evidence that Command rejects either on a non-standalone CA (see the
// doc comment on validateCAConfigConstraints), they are removed from the
// standalone-only constraint alongside allowed_enrollment_types and must
// never be rejected by ValidateConfig regardless of standalone's value.
func TestUnitCAValidateConfigNeverRejectsAllowedRequestersRegardlessOfStandalone(t *testing.T) {
	base := func() KeyfactorCertificateAuthority {
		cfg := caConstraintsAllUnset
		cfg.Standalone = types.Bool{Value: false}
		return cfg
	}

	useAllowedRequesters := base()
	useAllowedRequesters.UseAllowedRequesters = types.Bool{Value: true}
	assert.False(t, validateCAConfigConstraints(useAllowedRequesters).HasError(),
		"use_allowed_requesters=true with standalone=false must not be rejected")

	allowedRequesters := base()
	allowedRequesters.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.False(t, validateCAConfigConstraints(allowedRequesters).HasError(),
		"a non-empty allowed_requesters with standalone=false must not be rejected")
}

// TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneUnsetOrUnknown
// confirms standalone left undeclared or Unknown never trips any check
// (config-time validation can't resolve a computed/unresolved standalone
// value regardless).
func TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneUnsetOrUnknown(t *testing.T) {
	undeclared := caConstraintsAllUnset
	undeclared.AllowedEnrollmentTypes = types.Int64{Value: 2}
	undeclared.UseAllowedRequesters = types.Bool{Value: true}
	undeclared.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.False(t, validateCAConfigConstraints(undeclared).HasError(),
		"standalone left undeclared must never error -- config-time validation can't resolve a computed standalone value")

	unknown := undeclared
	unknown.Standalone = types.Bool{Unknown: true}
	assert.False(t, validateCAConfigConstraints(unknown).HasError(),
		"an unknown standalone (e.g. referencing another resource's not-yet-known output) must never error")
}

// TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneTrue is
// the passing case for a real standalone CA: all three formerly
// standalone-only attributes together must remain legal.
func TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneTrue(t *testing.T) {
	cfg := caConstraintsAllUnset
	cfg.Standalone = types.Bool{Value: true}
	cfg.AllowedEnrollmentTypes = types.Int64{Value: 2}
	cfg.UseAllowedRequesters = types.Bool{Value: true}
	cfg.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.False(t, validateCAConfigConstraints(cfg).HasError())
}
