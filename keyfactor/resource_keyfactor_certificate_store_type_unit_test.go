package keyfactor

import (
	"testing"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitCertStoreTypeExplicitBoolsReachRequest is a regression test for the
// bug where the boolean flags (local_store, server_required, power_shell,
// blueprint_allowed) were copied into plain-bool `,omitempty` SDK request
// fields, so an explicit false was dropped from the outgoing request and the
// server silently reverted the flag to its default. The request fields are now
// *bool, and certStoreTypeDefToAPIRequest sends the value only when the plan
// knows it — a known false must survive as a non-nil *false.
func TestUnitCertStoreTypeExplicitBoolsReachRequest(t *testing.T) {
	plan := KeyfactorCertStoreTypeDef{
		LocalStore:       types.Bool{Value: false},
		ServerRequired:   types.Bool{Value: false},
		PowerShell:       types.Bool{Value: false},
		BlueprintAllowed: types.Bool{Value: false},
	}

	req := certStoreTypeDefToAPIRequest(plan)

	if assert.NotNil(t, req.LocalStore, "explicit local_store=false must reach the request, not be dropped") {
		assert.False(t, *req.LocalStore)
	}
	if assert.NotNil(t, req.ServerRequired, "explicit server_required=false must reach the request") {
		assert.False(t, *req.ServerRequired)
	}
	if assert.NotNil(t, req.PowerShell, "explicit power_shell=false must reach the request") {
		assert.False(t, *req.PowerShell)
	}
	if assert.NotNil(t, req.BlueprintAllowed, "explicit blueprint_allowed=false must reach the request") {
		assert.False(t, *req.BlueprintAllowed)
	}

	// A known true still reaches the request as *true.
	planTrue := KeyfactorCertStoreTypeDef{LocalStore: types.Bool{Value: true}}
	reqTrue := certStoreTypeDefToAPIRequest(planTrue)
	if assert.NotNil(t, reqTrue.LocalStore) {
		assert.True(t, *reqTrue.LocalStore)
	}
}

// TestUnitCertStoreTypeUnknownBoolsOmitted verifies that Null/Unknown booleans
// are omitted (nil *bool) so Command applies its own default on create instead
// of us clobbering it with a spurious Go zero.
func TestUnitCertStoreTypeUnknownBoolsOmitted(t *testing.T) {
	plan := KeyfactorCertStoreTypeDef{
		LocalStore:       types.Bool{Unknown: true},
		ServerRequired:   types.Bool{Null: true},
		PowerShell:       types.Bool{Unknown: true},
		BlueprintAllowed: types.Bool{Null: true},
	}

	req := certStoreTypeDefToAPIRequest(plan)

	assert.Nil(t, req.LocalStore, "unknown local_store must be omitted")
	assert.Nil(t, req.ServerRequired, "null server_required must be omitted")
	assert.Nil(t, req.PowerShell, "unknown power_shell must be omitted")
	assert.Nil(t, req.BlueprintAllowed, "null blueprint_allowed must be omitted")
}

// TestUnitCertStoreTypeExplicitEmptyListsClear is a regression test for the bug
// where `properties = []` / `entry_parameters = []` (the user removed every
// block) was treated identically to "never configured" by a `len(x) > 0` guard,
// so the field was omitted and existing definitions were never cleared on
// Update. An explicit empty (non-nil) slice must now serialize as an empty list
// (a clear signal), while a nil slice stays omitted.
func TestUnitCertStoreTypeExplicitEmptyListsClear(t *testing.T) {
	// Explicit empty: the user cleared all blocks.
	planEmpty := KeyfactorCertStoreTypeDef{
		Properties:      []CertStoreTypeProperty{},
		EntryParameters: []CertStoreTypeEntryParam{},
	}
	reqEmpty := certStoreTypeDefToAPIRequest(planEmpty)

	if assert.NotNil(t, reqEmpty.Properties, "explicit properties=[] must be sent as a clear signal, not omitted") {
		assert.Len(t, *reqEmpty.Properties, 0)
	}
	if assert.NotNil(t, reqEmpty.EntryParameters, "explicit entry_parameters=[] must be sent as a clear signal") {
		assert.Len(t, *reqEmpty.EntryParameters, 0)
	}

	// Never configured: nil slice must be omitted so existing definitions are
	// left untouched.
	planNil := KeyfactorCertStoreTypeDef{
		Properties:      nil,
		EntryParameters: nil,
	}
	reqNil := certStoreTypeDefToAPIRequest(planNil)
	assert.Nil(t, reqNil.Properties, "unset properties must be omitted, not sent as an empty clear")
	assert.Nil(t, reqNil.EntryParameters, "unset entry_parameters must be omitted")
}

// TestUnitCertStoreTypeDefToState_BoolPointersPreserveNull is a regression
// test for certStoreTypeDefToState collapsing a nil *bool response field
// (local_store, server_required, power_shell, blueprint_allowed) to
// types.Bool{Value: false} via the derefBool helper, instead of
// types.Bool{Null: true}. A server that omits these Optional+Computed fields
// (nil pointer) must read into state as null, not a concrete false — a
// concrete false is indistinguishable from a server that actually reported
// false, and can cause "inconsistent result after apply" or silently mask
// real drift.
func TestUnitCertStoreTypeDefToState_BoolPointersPreserveNull(t *testing.T) {
	// All four pointers nil: must read as Null, not Value:false.
	respNil := &api.CertificateStoreType{
		Name:      "AGeneric",
		ShortName: "AGeneric",
		StoreType: 1,
	}
	stateNil := certStoreTypeDefToState(respNil)

	assert.True(t, stateNil.LocalStore.Null, "nil LocalStore must read as Null")
	assert.False(t, stateNil.LocalStore.Value, "Null LocalStore must not also carry Value:true")
	assert.True(t, stateNil.ServerRequired.Null, "nil ServerRequired must read as Null")
	assert.True(t, stateNil.PowerShell.Null, "nil PowerShell must read as Null")
	assert.True(t, stateNil.BlueprintAllowed.Null, "nil BlueprintAllowed must read as Null")

	// All four pointers explicitly false: must read as Value:false, Null:false.
	respFalse := &api.CertificateStoreType{
		Name:             "AGeneric",
		ShortName:        "AGeneric",
		StoreType:        1,
		LocalStore:       boolPtr(false),
		ServerRequired:   boolPtr(false),
		PowerShell:       boolPtr(false),
		BlueprintAllowed: boolPtr(false),
	}
	stateFalse := certStoreTypeDefToState(respFalse)

	assert.False(t, stateFalse.LocalStore.Null, "explicit false LocalStore must not read as Null")
	assert.False(t, stateFalse.LocalStore.Value)
	assert.False(t, stateFalse.ServerRequired.Null)
	assert.False(t, stateFalse.ServerRequired.Value)
	assert.False(t, stateFalse.PowerShell.Null)
	assert.False(t, stateFalse.PowerShell.Value)
	assert.False(t, stateFalse.BlueprintAllowed.Null)
	assert.False(t, stateFalse.BlueprintAllowed.Value)
}

// TestUnitCertStoreTypeToAttrValue_BoolPointersPreserveNull is the data-source
// counterpart of TestUnitCertStoreTypeDefToState_BoolPointersPreserveNull,
// covering certStoreTypeToAttrValue in
// data_source_keyfactor_certificate_store_types.go.
func TestUnitCertStoreTypeToAttrValue_BoolPointersPreserveNull(t *testing.T) {
	respNil := api.CertificateStoreType{
		Name:      "AGeneric",
		ShortName: "AGeneric",
		StoreType: 1,
	}
	objNil, ok := certStoreTypeToAttrValue(respNil).(types.Object)
	if !ok {
		t.Fatalf("expected certStoreTypeToAttrValue to return types.Object")
	}

	assertNullBool(t, objNil.Attrs, "local_store", true)
	assertNullBool(t, objNil.Attrs, "server_required", true)
	assertNullBool(t, objNil.Attrs, "power_shell", true)
	assertNullBool(t, objNil.Attrs, "blueprint_allowed", true)

	respFalse := api.CertificateStoreType{
		Name:             "AGeneric",
		ShortName:        "AGeneric",
		StoreType:        1,
		LocalStore:       boolPtr(false),
		ServerRequired:   boolPtr(false),
		PowerShell:       boolPtr(false),
		BlueprintAllowed: boolPtr(false),
	}
	objFalse, ok := certStoreTypeToAttrValue(respFalse).(types.Object)
	if !ok {
		t.Fatalf("expected certStoreTypeToAttrValue to return types.Object")
	}

	assertNullBool(t, objFalse.Attrs, "local_store", false)
	assertNullBool(t, objFalse.Attrs, "server_required", false)
	assertNullBool(t, objFalse.Attrs, "power_shell", false)
	assertNullBool(t, objFalse.Attrs, "blueprint_allowed", false)
}

// assertNullBool asserts attrs[key] is a types.Bool with the expected Null
// flag, and (when not null) an explicit false Value.
func assertNullBool(t *testing.T, attrs map[string]attr.Value, key string, wantNull bool) {
	t.Helper()
	v, ok := attrs[key]
	if !ok {
		t.Fatalf("expected attribute %q to be present", key)
	}
	b, ok := v.(types.Bool)
	if !ok {
		t.Fatalf("expected attribute %q to be types.Bool, got %T", key, v)
	}
	if b.Null != wantNull {
		t.Fatalf("attribute %q: expected Null=%v, got Null=%v Value=%v", key, wantNull, b.Null, b.Value)
	}
	if !wantNull && b.Value {
		t.Fatalf("attribute %q: expected Value=false, got Value=true", key)
	}
}
