package keyfactor

import (
	"context"
	"testing"

	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F8: mapOAuthSecurityRole is nil-safe for the optional Id and Immutable pointers.
func TestUnitMapOAuthSecurityRole_NilSafety(t *testing.T) {
	ctx := context.Background()
	id := int32(7)
	immutable := true
	name := "Admins"

	t.Run("missing Id is an error", func(t *testing.T) {
		data := &kfv2.SecuritySecurityRolesSecurityRoleResponse{Immutable: &immutable}
		data.Name.Set(&name)
		_, err := mapOAuthSecurityRole(ctx, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "without an ID")
	})
	t.Run("missing Immutable is null", func(t *testing.T) {
		data := &kfv2.SecuritySecurityRolesSecurityRoleResponse{Id: &id}
		got, err := mapOAuthSecurityRole(ctx, data)
		require.NoError(t, err)
		assert.Equal(t, int64(7), got.ID.Value)
		assert.True(t, got.Immutable.Null)
	})
	t.Run("present values are kept", func(t *testing.T) {
		data := &kfv2.SecuritySecurityRolesSecurityRoleResponse{Id: &id, Immutable: &immutable}
		got, err := mapOAuthSecurityRole(ctx, data)
		require.NoError(t, err)
		assert.False(t, got.Immutable.Null)
		assert.True(t, got.Immutable.Value)
	})
}
