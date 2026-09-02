package keyfactor

import (
	"testing"

	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
)

// TestUnitPAMProviderResponseToMetadata_NilPointerFields verifies that when the server omits
// Remote and Area in the response, the resulting Terraform state values are Null rather than
// the Go zero values (false / 0). This regression-tests the "inconsistent result after apply"
// bug for keyfactor_pam_provider — the schema marks both fields Optional+Computed, so a plan
// that omits them must round-trip to Null after Create/Read, not false/0.
func TestUnitPAMProviderResponseToMetadata_NilPointerFields(t *testing.T) {
	id := int32(7)
	resp := &v1.PAMProviderResponseLegacy{
		Id:     &id,
		Remote: nil, // server omitted Remote
		Area:   nil, // server omitted Area
	}
	resp.Name.Set(strPtr("tf-unit-pam"))

	state := pamProviderResponseToMetadata(resp)

	if !state.Remote.Null {
		t.Errorf("Remote: expected Null=true when server omits Remote, got Null=%v Value=%v",
			state.Remote.Null, state.Remote.Value)
	}
	if state.Remote.Value != false {
		// Defensive: even when Null, the underlying value should be the zero value (not load-bearing,
		// but documents intent).
		t.Logf("Remote.Value (when Null) = %v (expected zero)", state.Remote.Value)
	}
	if !state.Area.Null {
		t.Errorf("Area: expected Null=true when server omits Area, got Null=%v Value=%v",
			state.Area.Null, state.Area.Value)
	}
	if state.ID.Value != "7" {
		t.Errorf("ID: expected %q, got %q", "7", state.ID.Value)
	}
	if state.Name.Value != "tf-unit-pam" {
		t.Errorf("Name: expected %q, got %q", "tf-unit-pam", state.Name.Value)
	}
}

// strPtr returns a pointer to the given string for use in SDK struct construction.
func strPtr(s string) *string { return &s }

// TestUnitPAMProviderResponseToMetadata_SetFields verifies that when the server returns explicit
// values for Remote and Area, those values flow through to state correctly.
func TestUnitPAMProviderResponseToMetadata_SetFields(t *testing.T) {
	id := int32(42)
	remote := true
	area := int32(2)
	resp := &v1.PAMProviderResponseLegacy{
		Id:     &id,
		Remote: &remote,
		Area:   &area,
	}
	resp.Name.Set(strPtr("tf-unit-pam-set"))

	state := pamProviderResponseToMetadata(resp)

	if state.Remote.Null || state.Remote.Unknown {
		t.Errorf("Remote: expected concrete value, got Null=%v Unknown=%v", state.Remote.Null, state.Remote.Unknown)
	}
	if state.Remote.Value != true {
		t.Errorf("Remote.Value: expected true, got %v", state.Remote.Value)
	}
	if state.Area.Null || state.Area.Unknown {
		t.Errorf("Area: expected concrete value, got Null=%v Unknown=%v", state.Area.Null, state.Area.Unknown)
	}
	if state.Area.Value != 2 {
		t.Errorf("Area.Value: expected 2, got %v", state.Area.Value)
	}
}

// TestUnitBoolPtrToTfBool exercises the helper directly across both branches.
func TestUnitBoolPtrToTfBool(t *testing.T) {
	got := boolPtrToTfBool(nil)
	if !got.Null {
		t.Errorf("boolPtrToTfBool(nil): expected Null=true, got Null=%v", got.Null)
	}
	b := true
	got = boolPtrToTfBool(&b)
	if got.Null || got.Value != true {
		t.Errorf("boolPtrToTfBool(&true): expected Null=false Value=true, got Null=%v Value=%v",
			got.Null, got.Value)
	}
}

// TestUnitInt32PtrToTfInt64 exercises the helper directly across both branches.
func TestUnitInt32PtrToTfInt64(t *testing.T) {
	got := int32PtrToTfInt64(nil)
	if !got.Null {
		t.Errorf("int32PtrToTfInt64(nil): expected Null=true, got Null=%v", got.Null)
	}
	i := int32(5)
	got = int32PtrToTfInt64(&i)
	if got.Null || got.Value != 5 {
		t.Errorf("int32PtrToTfInt64(&5): expected Null=false Value=5, got Null=%v Value=%v",
			got.Null, got.Value)
	}
}
