package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Regression tests for owner_role_name's declarative-clear attribute
// contract:
//
//   - Omitting owner_role_name from config (Null/Unknown plan) leaves
//     ownership unmanaged -- Terraform must never send a clearing PUT just
//     because the attribute wasn't declared.
//   - Declaring an explicit empty string ("") is a declarative "clear the
//     owner" sentinel: Terraform sends a PUT with no role identifier, which
//     Command interprets as removing the owner.
//   - The "" sentinel must stay stable across refreshes: once cleared,
//     Read must not collapse state back to Null (which would manufacture a
//     permanent "" -> null -> "" diff against a config that still declares
//     "").
//
// Before this fix, Update's inline check was simply
// `plan.OwnerRoleName.Value != state.OwnerRoleName.Value`. Since a Null
// types.String's .Value is the Go zero value (""), an undeclared plan
// (Null) compared against a real prior owner (e.g. "AdministratorsRole")
// evaluated to true -- wrongly firing the clear path and sending
// {"NewRoleName":""} to PUT /Certificates/{id}/Owner purely because config
// omitted the attribute, not because the user asked to clear it. Read
// separately collapsed any empty OwnerRoleName straight to Null via
// isNullString, discarding a declared "" sentinel on every refresh.
// ---------------------------------------------------------------------------

// TestUnitCertificateOwnerRoleChanged_UndeclaredPlanNeverFires reproduces the
// root regression directly against the old inline expression and the new
// guarded helper: an undeclared (Null) plan value must never be treated as a
// change, no matter what real owner is in prior state.
func TestUnitCertificateOwnerRoleChanged_UndeclaredPlanNeverFires(t *testing.T) {
	state := CommandCertificate{OwnerRoleName: types.String{Value: "AdministratorsRole"}}
	plan := CommandCertificate{OwnerRoleName: types.String{Null: true}}

	// The pre-fix inline check this resource used before
	// certificateOwnerRoleChanged existed: plan.OwnerRoleName.Value !=
	// state.OwnerRoleName.Value. A Null types.String's .Value is "", so this
	// wrongly evaluates to true for an undeclared plan against a real owner.
	oldInlineCheck := plan.OwnerRoleName.Value != state.OwnerRoleName.Value
	if !oldInlineCheck {
		t.Fatalf("test setup: expected the old inline expression to reproduce the bug (true) for this fixture")
	}

	if got := certificateOwnerRoleChanged(plan, state); got {
		t.Fatalf(
			"certificateOwnerRoleChanged(undeclared plan, state=%q) = true, want false -- "+
				"omitting owner_role_name from config must never be treated as a request to clear the owner",
			state.OwnerRoleName.Value,
		)
	}
}

// TestUnitCertificateOwnerRoleChanged_UnknownPlanNeverFires mirrors the Null
// case for an Unknown plan value (e.g. mid-plan before a value is resolved).
func TestUnitCertificateOwnerRoleChanged_UnknownPlanNeverFires(t *testing.T) {
	state := CommandCertificate{OwnerRoleName: types.String{Value: "AdministratorsRole"}}
	plan := CommandCertificate{OwnerRoleName: types.String{Unknown: true}}

	if got := certificateOwnerRoleChanged(plan, state); got {
		t.Fatalf("certificateOwnerRoleChanged(unknown plan, state=%q) = true, want false", state.OwnerRoleName.Value)
	}
}

// TestUnitCertificateOwnerRoleChanged_ExplicitClearFires asserts that a
// declared owner_role_name = "" (Known, empty) DOES fire when prior state
// held a real owner -- the declarative clear path must still work.
func TestUnitCertificateOwnerRoleChanged_ExplicitClearFires(t *testing.T) {
	state := CommandCertificate{OwnerRoleName: types.String{Value: "AdministratorsRole"}}
	plan := CommandCertificate{OwnerRoleName: types.String{Value: ""}}

	if got := certificateOwnerRoleChanged(plan, state); !got {
		t.Fatalf("certificateOwnerRoleChanged(explicit \"\" plan, state=%q) = false, want true -- an explicit empty string must still trigger the clear path", state.OwnerRoleName.Value)
	}
}

// TestUnitCertificateOwnerRoleChanged_RealChangeFires asserts the ordinary
// case (declaring a different real role) still fires.
func TestUnitCertificateOwnerRoleChanged_RealChangeFires(t *testing.T) {
	state := CommandCertificate{OwnerRoleName: types.String{Value: "AdministratorsRole"}}
	plan := CommandCertificate{OwnerRoleName: types.String{Value: "AuditorsRole"}}

	if got := certificateOwnerRoleChanged(plan, state); !got {
		t.Fatalf("certificateOwnerRoleChanged(plan=%q, state=%q) = false, want true", plan.OwnerRoleName.Value, state.OwnerRoleName.Value)
	}
}

// TestUnitCertificateOwnerRoleChanged_NoOpDoesNotFire asserts that declaring
// the same value already in state does not fire.
func TestUnitCertificateOwnerRoleChanged_NoOpDoesNotFire(t *testing.T) {
	state := CommandCertificate{OwnerRoleName: types.String{Value: "AdministratorsRole"}}
	plan := CommandCertificate{OwnerRoleName: types.String{Value: "AdministratorsRole"}}

	if got := certificateOwnerRoleChanged(plan, state); got {
		t.Fatalf("certificateOwnerRoleChanged(plan=%q, state=%q) = true, want false", plan.OwnerRoleName.Value, state.OwnerRoleName.Value)
	}
}

// TestUnitOwnerChangeRequestForPlan_EmptyClearsBothFields asserts the
// declarative clear sentinel builds an empty OwnerRequest -- per Command's
// PUT /Certificates/{id}/Owner Swagger doc ("If removing the owner, leave
// both empty"), NewRoleId and NewRoleName must both be nil (not, e.g.,
// NewRoleName pointing at an empty string, which encoding/json's omitempty
// would NOT omit since it only checks for a nil pointer).
func TestUnitOwnerChangeRequestForPlan_EmptyClearsBothFields(t *testing.T) {
	req := ownerChangeRequestForPlan("")
	if req == nil {
		t.Fatal("ownerChangeRequestForPlan(\"\") returned nil")
	}
	if req.NewRoleId != nil {
		t.Errorf("ownerChangeRequestForPlan(\"\").NewRoleId = %v, want nil", *req.NewRoleId)
	}
	if req.NewRoleName != nil {
		t.Errorf("ownerChangeRequestForPlan(\"\").NewRoleName = %v, want nil", *req.NewRoleName)
	}
}

// TestUnitOwnerChangeRequestForPlan_NumericIsRoleID asserts a numeric string
// is sent as NewRoleId, not NewRoleName.
func TestUnitOwnerChangeRequestForPlan_NumericIsRoleID(t *testing.T) {
	req := ownerChangeRequestForPlan("5")
	if req.NewRoleId == nil || *req.NewRoleId != 5 {
		t.Errorf("ownerChangeRequestForPlan(\"5\").NewRoleId = %v, want 5", req.NewRoleId)
	}
	if req.NewRoleName != nil {
		t.Errorf("ownerChangeRequestForPlan(\"5\").NewRoleName = %v, want nil", *req.NewRoleName)
	}
}

// TestUnitOwnerChangeRequestForPlan_NameIsRoleName asserts a non-numeric
// string is sent as NewRoleName.
func TestUnitOwnerChangeRequestForPlan_NameIsRoleName(t *testing.T) {
	req := ownerChangeRequestForPlan("AdministratorsRole")
	if req.NewRoleName == nil || *req.NewRoleName != "AdministratorsRole" {
		t.Errorf("ownerChangeRequestForPlan(\"AdministratorsRole\").NewRoleName = %v, want \"AdministratorsRole\"", req.NewRoleName)
	}
	if req.NewRoleId != nil {
		t.Errorf("ownerChangeRequestForPlan(\"AdministratorsRole\").NewRoleId = %v, want nil", *req.NewRoleId)
	}
}

// TestUnitOwnerRoleNameForRead_ServerValueAlwaysWins asserts a real
// server-reported owner is always surfaced, even over a stale "" sentinel in
// prior state -- an out-of-band (or this resource's own prior Update) owner
// change must always be drift-visible.
func TestUnitOwnerRoleNameForRead_ServerValueAlwaysWins(t *testing.T) {
	got := ownerRoleNameForRead("AdministratorsRole", types.String{Value: ""})
	if got.Null || got.Value != "AdministratorsRole" {
		t.Errorf("ownerRoleNameForRead(server=%q, prior=\"\") = %+v, want Known \"AdministratorsRole\"", "AdministratorsRole", got)
	}
}

// TestUnitOwnerRoleNameForRead_SentinelStaysStable is the direct regression
// test for sentinel stability: once the owner is cleared (server reports ""
// and prior state already held the "" sentinel from a prior declarative
// clear), Read must keep state at "" rather than collapsing to Null. Without
// this, a config that still declares owner_role_name = "" would see a
// perpetual "" -> null -> "" diff on every plan.
func TestUnitOwnerRoleNameForRead_SentinelStaysStable(t *testing.T) {
	got := ownerRoleNameForRead("", types.String{Value: ""})
	if got.Null {
		t.Fatalf("ownerRoleNameForRead(server=\"\", prior=\"\" sentinel) = %+v, want Known \"\" (sentinel preserved), got Null", got)
	}
	if got.Value != "" {
		t.Errorf("ownerRoleNameForRead(server=\"\", prior=\"\" sentinel).Value = %q, want \"\"", got.Value)
	}
}

// TestUnitOwnerRoleNameForRead_UndeclaredStaysNull asserts that when
// owner_role_name has never been declared (prior state Null) and the server
// reports no owner, Read leaves it Null -- the attribute stays unmanaged
// rather than acquiring a "" sentinel it was never given.
func TestUnitOwnerRoleNameForRead_UndeclaredStaysNull(t *testing.T) {
	got := ownerRoleNameForRead("", types.String{Null: true})
	if !got.Null {
		t.Errorf("ownerRoleNameForRead(server=\"\", prior=Null) = %+v, want Null", got)
	}
}

// TestUnitOwnerRoleNameForRead_UnknownStaysNull covers the Unknown prior
// case (e.g. first Read immediately after Create) the same way as Null.
func TestUnitOwnerRoleNameForRead_UnknownStaysNull(t *testing.T) {
	got := ownerRoleNameForRead("", types.String{Unknown: true})
	if !got.Null {
		t.Errorf("ownerRoleNameForRead(server=\"\", prior=Unknown) = %+v, want Null", got)
	}
}
