package keyfactor

import (
	"context"
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitTemplateUpdateRequestExplicitEmptyLists is a regression test for the
// four `len(x) > 0` gating bugs in buildTemplateUpdateRequest. An explicit
// empty list (the user removed every block) was indistinguishable from the
// attribute never being configured, so the field was dropped from the outgoing
// update request entirely instead of clearing the entries server-side. The fix
// gates on != nil and builds a non-nil (possibly empty) slice; the SDK's ToMap
// serializes a non-nil empty slice as [] (clear) but omits a nil slice.
func TestUnitTemplateUpdateRequestExplicitEmptyLists(t *testing.T) {
	ctx := context.Background()

	// Explicit empty: every list cleared. Each must reach the request as a
	// non-nil empty slice (serialized as [] — a clear signal).
	planCleared := KeyfactorCertificateTemplateState{
		ID:               types.Int64{Value: 7},
		TemplateRegexes:  []TemplateRegexEntry{},
		TemplateDefaults: []TemplateDefaultEntry{},
		EnrollmentFields: []TemplateEnrollmentFieldEntry{},
		MetadataFields:   []TemplateMetadataFieldEntry{},
	}
	reqCleared := buildTemplateUpdateRequest(ctx, planCleared)

	assert.NotNil(t, reqCleared.TemplateRegexes, "explicit template_regexes=[] must reach the request as a clear signal")
	assert.Len(t, reqCleared.TemplateRegexes, 0)
	assert.NotNil(t, reqCleared.TemplateDefaults, "explicit template_defaults=[] must reach the request as a clear signal")
	assert.Len(t, reqCleared.TemplateDefaults, 0)
	assert.NotNil(t, reqCleared.EnrollmentFields, "explicit enrollment_fields=[] must reach the request as a clear signal")
	assert.Len(t, reqCleared.EnrollmentFields, 0)
	assert.NotNil(t, reqCleared.MetadataFields, "explicit metadata_fields=[] must reach the request as a clear signal")
	assert.Len(t, reqCleared.MetadataFields, 0)

	// Never configured: nil slices must be omitted (nil) so existing entries are
	// left untouched.
	planUndeclared := KeyfactorCertificateTemplateState{
		ID:               types.Int64{Value: 7},
		TemplateRegexes:  nil,
		TemplateDefaults: nil,
		EnrollmentFields: nil,
		MetadataFields:   nil,
	}
	reqUndeclared := buildTemplateUpdateRequest(ctx, planUndeclared)

	assert.Nil(t, reqUndeclared.TemplateRegexes, "undeclared template_regexes must be omitted, not cleared")
	assert.Nil(t, reqUndeclared.TemplateDefaults, "undeclared template_defaults must be omitted, not cleared")
	assert.Nil(t, reqUndeclared.EnrollmentFields, "undeclared enrollment_fields must be omitted, not cleared")
	assert.Nil(t, reqUndeclared.MetadataFields, "undeclared metadata_fields must be omitted, not cleared")
}

func TestUnitTemplateResponseToState_NilPolicyFields(t *testing.T) {
	resp := &v1.TemplatesTemplateRetrievalResponse{}
	id := int32(42)
	resp.SetId(id)
	resp.SetCommonName("TestTemplate")
	resp.SetTemplateName("TestTemplate")

	resp.TemplatePolicy = &v1.TemplatesTemplatePolicyResponseModel{}

	state := templateResponseToState(resp)

	if state.TemplatePolicy == nil {
		t.Fatal("expected TemplatePolicy to be non-nil")
	}

	pol := state.TemplatePolicy
	if !pol.AllowKeyReuse.Null {
		t.Errorf("AllowKeyReuse: expected Null=true, got Value=%v Null=%v", pol.AllowKeyReuse.Value, pol.AllowKeyReuse.Null)
	}
	if !pol.AllowWildcards.Null {
		t.Errorf("AllowWildcards: expected Null=true, got Value=%v Null=%v", pol.AllowWildcards.Value, pol.AllowWildcards.Null)
	}
	if !pol.RFCEnforcement.Null {
		t.Errorf("RFCEnforcement: expected Null=true, got Value=%v Null=%v", pol.RFCEnforcement.Value, pol.RFCEnforcement.Null)
	}
	if !pol.CertificateOwnerRole.Null {
		t.Errorf("CertificateOwnerRole: expected Null=true, got Value=%v Null=%v", pol.CertificateOwnerRole.Value, pol.CertificateOwnerRole.Null)
	}
}

func TestUnitTemplateResponseToState_SetPolicyFields(t *testing.T) {
	resp := &v1.TemplatesTemplateRetrievalResponse{}
	id := int32(42)
	resp.SetId(id)
	resp.SetCommonName("TestTemplate")
	resp.SetTemplateName("TestTemplate")

	bTrue := true
	bFalse := false
	role := v1.CSSCMSCoreEnumsTemplateCertificateOwnerRole(1)

	pol := &v1.TemplatesTemplatePolicyResponseModel{
		CertificateOwnerRole: &role,
	}
	pol.AllowKeyReuse.Set(&bTrue)
	pol.AllowWildcards.Set(&bFalse)
	pol.RFCEnforcement.Set(&bTrue)

	resp.TemplatePolicy = pol

	state := templateResponseToState(resp)

	if state.TemplatePolicy == nil {
		t.Fatal("expected TemplatePolicy to be non-nil")
	}

	sp := state.TemplatePolicy
	if sp.AllowKeyReuse.Null || sp.AllowKeyReuse.Value != true {
		t.Errorf("AllowKeyReuse: expected Value=true, got Value=%v Null=%v", sp.AllowKeyReuse.Value, sp.AllowKeyReuse.Null)
	}
	if sp.AllowWildcards.Null || sp.AllowWildcards.Value != false {
		t.Errorf("AllowWildcards: expected Value=false, got Value=%v Null=%v", sp.AllowWildcards.Value, sp.AllowWildcards.Null)
	}
	if sp.RFCEnforcement.Null || sp.RFCEnforcement.Value != true {
		t.Errorf("RFCEnforcement: expected Value=true, got Value=%v Null=%v", sp.RFCEnforcement.Value, sp.RFCEnforcement.Null)
	}
	if sp.CertificateOwnerRole.Null || sp.CertificateOwnerRole.Value != 1 {
		t.Errorf("CertificateOwnerRole: expected Value=1, got Value=%v Null=%v", sp.CertificateOwnerRole.Value, sp.CertificateOwnerRole.Null)
	}
}

func TestUnitTemplateResponseToState_NilPolicy(t *testing.T) {
	resp := &v1.TemplatesTemplateRetrievalResponse{}
	resp.SetId(42)
	resp.SetCommonName("TestTemplate")
	resp.TemplatePolicy = nil

	state := templateResponseToState(resp)
	if state.TemplatePolicy != nil {
		t.Errorf("expected TemplatePolicy to be nil when API returns nil, got %+v", state.TemplatePolicy)
	}
}

// TestUnitTemplateSchema_V25CleanupFieldsUseStateForUnknown is a regression test
// for the four Command v25+ Optional+Computed cleanup attributes
// (certificate_cleanup_enabled, time_after_expiration, time_after_expiration_units,
// delete_with_archived_key) that were missing the UseStateForUnknown plan modifier
// carried by every other Optional+Computed scalar in this schema (e.g.
// friendly_name, key_retention, requires_approval). Without it, Terraform Core
// marks these attributes "unknown" on any plan where the config doesn't declare
// them, and the subsequent apply's actual (state-derived) value differs from the
// planned "unknown" placeholder — producing "Provider produced inconsistent
// result after apply."
func TestUnitTemplateSchema_V25CleanupFieldsUseStateForUnknown(t *testing.T) {
	ctx := context.Background()

	schema, diags := resourceCertificateTemplateType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", diags)
	}

	fields := []string{
		"certificate_cleanup_enabled",
		"time_after_expiration",
		"time_after_expiration_units",
		"delete_with_archived_key",
	}

	for _, name := range fields {
		attr, ok := schema.Attributes[name]
		if !ok {
			t.Fatalf("expected schema attribute %q to exist", name)
		}
		if !attr.Optional || !attr.Computed {
			t.Fatalf("attribute %q: expected Optional+Computed, got Optional=%v Computed=%v", name, attr.Optional, attr.Computed)
		}

		found := false
		for _, m := range attr.PlanModifiers {
			if _, ok := m.(tfsdk.UseStateForUnknownModifier); ok {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("attribute %q: expected UseStateForUnknown plan modifier so it carries forward from state when unset in plan, but none was found (modifiers: %+v)", name, attr.PlanModifiers)
		}
	}
}
