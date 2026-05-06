package keyfactor

import (
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
)

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
