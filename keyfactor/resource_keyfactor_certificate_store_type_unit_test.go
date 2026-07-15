package keyfactor

import (
	"testing"

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
