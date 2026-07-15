package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

// TestUnitSecurityRoleUpdateArgPermissions is a regression test for the bug
// where a Null (undeclared) permissions attribute resolved to a nil Go slice
// that was still wrapped in a non-nil pointer (&permissions). The non-nil
// pointer bypassed the SDK's `omitempty`, so the request marshaled as
// `"Permissions": null` and cleared every permission the role had. permissions
// is Optional (not Computed): Null must omit the field (preserve), while an
// explicit empty list must be sent as [] (clear).
func TestUnitSecurityRoleUpdateArgPermissions(t *testing.T) {
	ctx := context.Background()

	t.Run("undeclared permissions omits the field (preserve)", func(t *testing.T) {
		plan := SecurityRole{
			Name:        types.String{Value: "role"},
			Permissions: types.List{Null: true, ElemType: types.StringType},
		}
		arg := buildSecurityRoleUpdateArg(ctx, plan, 5)
		assert.Nil(t, arg.Permissions,
			"undeclared permissions must be omitted so Command preserves the role's existing permissions")
	})

	t.Run("explicit empty list clears", func(t *testing.T) {
		plan := SecurityRole{
			Name:        types.String{Value: "role"},
			Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{}},
		}
		arg := buildSecurityRoleUpdateArg(ctx, plan, 5)
		if assert.NotNil(t, arg.Permissions, "explicit permissions=[] must be sent as a clear signal") {
			assert.Equal(t, []string{}, *arg.Permissions,
				"an explicit empty permissions list must serialize as [] (clear), not null")
		}
	})

	t.Run("populated permissions are sent", func(t *testing.T) {
		plan := SecurityRole{
			Name: types.String{Value: "role"},
			Permissions: types.List{ElemType: types.StringType, Elems: []attr.Value{
				types.String{Value: "certificates:read"},
				types.String{Value: "auditing:read"},
			}},
		}
		arg := buildSecurityRoleUpdateArg(ctx, plan, 5)
		if assert.NotNil(t, arg.Permissions) {
			assert.ElementsMatch(t, []string{"certificates:read", "auditing:read"}, *arg.Permissions)
		}
	})
}
