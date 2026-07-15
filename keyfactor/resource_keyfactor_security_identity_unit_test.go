package keyfactor

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitSecurityIdentityRolesDeclared is a regression test for the bug where
// Update() always ran setIdentityRole (a full-replace sync of the identity's
// role assignments), even when the roles attribute was simply omitted from
// config (Null). That conflated "roles undeclared" with "roles explicitly
// emptied" and stripped every real role assignment on any unrelated Update.
//
// roles is Optional (not Computed): a Null value means preserve existing
// assignments (do not sync), while a non-null value — including an explicit
// empty list — is a full-replace instruction (an empty list clears all roles).
func TestUnitSecurityIdentityRolesDeclared(t *testing.T) {
	cases := []struct {
		name        string
		roles       types.List
		wantReplace bool
		reason      string
	}{
		{
			name:        "roles undeclared (null) -> preserve",
			roles:       types.List{Null: true, ElemType: types.StringType},
			wantReplace: false,
			reason:      "an undeclared roles attribute must preserve existing assignments, not full-replace",
		},
		{
			name:        "roles unknown -> preserve",
			roles:       types.List{Unknown: true, ElemType: types.StringType},
			wantReplace: false,
			reason:      "an unknown roles value must not trigger a destructive full-replace",
		},
		{
			name:        "roles explicitly empty -> clear",
			roles:       types.List{ElemType: types.StringType, Elems: []attr.Value{}},
			wantReplace: true,
			reason:      "an explicit empty list must still full-replace (clearing all roles)",
		},
		{
			name: "roles populated -> replace",
			roles: types.List{ElemType: types.StringType, Elems: []attr.Value{
				types.String{Value: "Administrator"},
			}},
			wantReplace: true,
			reason:      "a populated roles list must full-replace",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := SecurityIdentity{Roles: tc.roles}
			assert.Equal(t, tc.wantReplace, identityRolesDeclared(plan), tc.reason)
		})
	}
}
