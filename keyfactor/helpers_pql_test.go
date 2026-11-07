package keyfactor

import (
	"context"
	"testing"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
)

func testRole(id int32, name string) kfv2.SecuritySecurityRolesSecurityRoleQueryResponse {
	r := kfv2.SecuritySecurityRolesSecurityRoleQueryResponse{Id: &id}
	r.Name.Set(&name)
	return r
}

func testClaim(id int32, value, scheme string) kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse {
	c := kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{Id: &id}
	c.ClaimValue.Set(&value)
	p := kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionProviderResponse{}
	p.AuthenticationScheme.Set(&scheme)
	c.Provider = &p
	return c
}

// The quote guards run before any API access, so a nil client proves no query is issued.
func TestUnitGetSecurityRoleByName_RejectsQuote(t *testing.T) {
	_, err := getSecurityRoleByName(context.Background(), nil, `x") or (Name -ne "`)
	if !assert.Error(t, err) {
		return
	}
	assert.Contains(t, err.Error(), "double quote")
}

func TestUnitGetSecurityClaimByTypeAndValueAndScheme_RejectsQuote(t *testing.T) {
	_, err := getSecurityClaimByTypeAndValueAndScheme(context.Background(), nil, "OAuthSubject", `a" or ClaimValue -ne "b`, "System")
	if !assert.Error(t, err) {
		return
	}
	assert.Contains(t, err.Error(), "double quote")
}

func TestUnitSelectSecurityRoleByExactName(t *testing.T) {
	roles := []kfv2.SecuritySecurityRolesSecurityRoleQueryResponse{
		testRole(1, "Administrators-Extra"),
		testRole(2, "administrators"),
		testRole(3, "Administrators"),
	}
	got := selectSecurityRoleByExactName(roles, "Administrators")
	if !assert.NotNil(t, got) {
		return
	}
	assert.Equal(t, int32(2), *got.Id, "first case-insensitive exact match wins; prefix match is skipped")

	assert.Nil(t, selectSecurityRoleByExactName(roles, "Admin"))
	assert.Nil(t, selectSecurityRoleByExactName(nil, "Administrators"))
}

func TestUnitSelectSecurityClaimByValueAndScheme(t *testing.T) {
	claims := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{
		testClaim(1, "other", "System"),
		testClaim(2, "Alice", "Okta"),
		testClaim(3, "alice", "System"),
	}
	got := selectSecurityClaimByValueAndScheme(claims, "ALICE", "System")
	if !assert.NotNil(t, got) {
		return
	}
	assert.Equal(t, int32(3), *got.Id, "must match both value (case-insensitive) and scheme")

	assert.Nil(t, selectSecurityClaimByValueAndScheme(claims, "alice", "Missing"))
	assert.Nil(t, selectSecurityClaimByValueAndScheme(claims, "nobody", "System"))
	assert.Nil(t, selectSecurityClaimByValueAndScheme(nil, "alice", "System"))
}

func TestUnitIncludePrivateKeyOrDefault(t *testing.T) {
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Null: true}))
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Unknown: true}))
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Value: true}))
	assert.False(t, includePrivateKeyOrDefault(types.Bool{Value: false}))
}

func TestUnitIncludePrivateKeyReplaceNeeded(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	cases := []struct {
		name          string
		state, config types.Bool
		want          bool
	}{
		{"null->null", null, null, false},
		{"null->true", null, tr, false},
		{"null->false", null, fa, true},
		{"true->false", tr, fa, true},
		{"false->true", fa, tr, true},
		{"true->true", tr, tr, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, includePrivateKeyReplaceNeeded(c.state, c.config))
		})
	}
}

func TestUnitIncludePrivateKeyStateValue(t *testing.T) {
	// Null plan (state predates attribute, no config) must stay null to avoid
	// "inconsistent result after apply"; unknown resolves to the default.
	assert.True(t, includePrivateKeyStateValue(types.Bool{Null: true}).Null)
	assert.Equal(t, types.Bool{Value: true}, includePrivateKeyStateValue(types.Bool{Unknown: true}))
	assert.Equal(t, types.Bool{Value: true}, includePrivateKeyStateValue(types.Bool{Value: true}))
	assert.Equal(t, types.Bool{Value: false}, includePrivateKeyStateValue(types.Bool{Value: false}))
}
