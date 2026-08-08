package keyfactor

import (
	"context"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// F9: auth certificate metadata else-null branch
// ---------------------------------------------------------------------------

// TestUnitCAReadAuthCertificateMetadataNullWhenAbsent is the red/green
// regression test for F9: caResponseToState only set
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
// F1: properties JSON-normalization plan modifier
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
// regression test for F1: normalizePropertiesJSON was defined but never
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
		AttributeState: state,
		AttributePlan:  plan,
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
// is the concrete "red" reproduction for F1, run against the schema's actual
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
		AttributeState: state,
		AttributePlan:  types.String{Unknown: true},
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

// ---------------------------------------------------------------------------
// F3/F4: ValidateConfig constraint enforcement
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

// TestUnitCAValidateConfigRejectsEnforceUniqueDNWithNewEndEntity is the F3
// regression: enforce_unique_dn and new_end_entity_on_renew_and_reissue are
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
// the non-error cases for the F3 pair: either attribute alone, or neither
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

// TestUnitCAValidateConfigRejectsNewEndEntityFalseForHTTPSCa is the F4
// regression: new_end_entity_on_renew_and_reissue is documented as required
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

// TestUnitCAValidateConfigRejectsStandaloneOnlyAttributesWithStandaloneFalse
// is the F4 regression for allowed_enrollment_types/use_allowed_requesters/
// allowed_requesters: each is documented as applying to standalone CAs only,
// but before this fix none of them were rejected when standalone was
// explicitly declared false.
func TestUnitCAValidateConfigRejectsStandaloneOnlyAttributesWithStandaloneFalse(t *testing.T) {
	base := func() KeyfactorCertificateAuthority {
		cfg := caConstraintsAllUnset
		cfg.Standalone = types.Bool{Value: false}
		return cfg
	}

	allowedEnrollmentTypes := base()
	allowedEnrollmentTypes.AllowedEnrollmentTypes = types.Int64{Value: 2}
	assert.True(t, validateCAConfigConstraints(allowedEnrollmentTypes).HasError(),
		"allowed_enrollment_types requires standalone=true")

	useAllowedRequesters := base()
	useAllowedRequesters.UseAllowedRequesters = types.Bool{Value: true}
	assert.True(t, validateCAConfigConstraints(useAllowedRequesters).HasError(),
		"use_allowed_requesters applies to standalone CAs only")

	allowedRequesters := base()
	allowedRequesters.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.True(t, validateCAConfigConstraints(allowedRequesters).HasError(),
		"allowed_requesters applies to standalone CAs only")
}

// TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneUnsetOrUnknown
// confirms that config-time validation can't resolve a computed/unresolved
// standalone value, so leaving it undeclared or Unknown must never trip
// these checks regardless of what the standalone-only attributes are set to.
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
// the passing case for a real standalone CA: all three standalone-only
// attributes together must remain legal.
func TestUnitCAValidateConfigAllowsStandaloneOnlyAttributesWhenStandaloneTrue(t *testing.T) {
	cfg := caConstraintsAllUnset
	cfg.Standalone = types.Bool{Value: true}
	cfg.AllowedEnrollmentTypes = types.Int64{Value: 2}
	cfg.UseAllowedRequesters = types.Bool{Value: true}
	cfg.AllowedRequesters = stringSliceToTfList([]string{"Administrator"})
	assert.False(t, validateCAConfigConstraints(cfg).HasError())
}
