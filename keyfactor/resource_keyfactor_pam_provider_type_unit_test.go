package keyfactor

import (
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v24/api/keyfactor/v1"
)

// TestUnitPAMProviderTypeResponseToState_NilParameterFields verifies that when the server omits
// DisplayName and InstanceLevel on a parameter, the resulting Terraform state values are Null
// rather than the Go zero values ("" / false). This regression-tests the "inconsistent result
// after apply" bug for keyfactor_pam_provider_type — both fields are Optional+Computed in the
// schema, so plan-vs-state must match across the Create/Read boundary.
func TestUnitPAMProviderTypeResponseToState_NilParameterFields(t *testing.T) {
	typeID := "abcd-1234"
	paramID := int32(11)
	dt := v1.CSSCMSDataModelEnumsPamParameterDataType(int32(1))

	param := v1.PAMProviderTypeParameterResponse{
		Id:            &paramID,
		DataType:      &dt,
		InstanceLevel: nil, // server omitted InstanceLevel
		// DisplayName left zero-value (NullableString unset)
	}
	param.Name.Set(strPtr("Host"))

	resp := &v1.PAMProviderTypeResponse{
		Id:         &typeID,
		Parameters: []v1.PAMProviderTypeParameterResponse{param},
	}
	resp.Name.Set(strPtr("tf-unit-pamtype"))

	state := pamProviderTypeResponseToState(resp)

	if len(state.Parameters) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(state.Parameters))
	}
	p := state.Parameters[0]

	if !p.DisplayName.Null {
		t.Errorf("DisplayName: expected Null=true when server omits DisplayName, got Null=%v Value=%q",
			p.DisplayName.Null, p.DisplayName.Value)
	}
	if !p.InstanceLevel.Null {
		t.Errorf("InstanceLevel: expected Null=true when server omits InstanceLevel, got Null=%v Value=%v",
			p.InstanceLevel.Null, p.InstanceLevel.Value)
	}
	if p.Name.Value != "Host" {
		t.Errorf("Name: expected %q, got %q", "Host", p.Name.Value)
	}
	if p.DataType.Value != 1 {
		t.Errorf("DataType: expected 1, got %d", p.DataType.Value)
	}
}

// TestUnitPAMProviderTypeResponseToState_SetParameterFields verifies that when the server returns
// explicit values for DisplayName and InstanceLevel, those values flow through to state correctly.
func TestUnitPAMProviderTypeResponseToState_SetParameterFields(t *testing.T) {
	typeID := "guid-set"
	paramID := int32(22)
	dt := v1.CSSCMSDataModelEnumsPamParameterDataType(int32(2))
	instLevel := true

	param := v1.PAMProviderTypeParameterResponse{
		Id:            &paramID,
		DataType:      &dt,
		InstanceLevel: &instLevel,
	}
	param.Name.Set(strPtr("ApiKey"))
	param.DisplayName.Set(strPtr("PAM API Key"))

	resp := &v1.PAMProviderTypeResponse{
		Id:         &typeID,
		Parameters: []v1.PAMProviderTypeParameterResponse{param},
	}
	resp.Name.Set(strPtr("tf-unit-pamtype-set"))

	state := pamProviderTypeResponseToState(resp)

	if len(state.Parameters) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(state.Parameters))
	}
	p := state.Parameters[0]

	if p.DisplayName.Null || p.DisplayName.Unknown {
		t.Errorf("DisplayName: expected concrete value, got Null=%v Unknown=%v",
			p.DisplayName.Null, p.DisplayName.Unknown)
	}
	if p.DisplayName.Value != "PAM API Key" {
		t.Errorf("DisplayName.Value: expected %q, got %q", "PAM API Key", p.DisplayName.Value)
	}
	if p.InstanceLevel.Null || p.InstanceLevel.Unknown {
		t.Errorf("InstanceLevel: expected concrete value, got Null=%v Unknown=%v",
			p.InstanceLevel.Null, p.InstanceLevel.Unknown)
	}
	if p.InstanceLevel.Value != true {
		t.Errorf("InstanceLevel.Value: expected true, got %v", p.InstanceLevel.Value)
	}
}
