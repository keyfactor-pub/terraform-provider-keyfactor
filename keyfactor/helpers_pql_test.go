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
	got, err := selectSecurityRoleByExactName(roles, "Administrators")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(3), *got.Id, "exact-case match preferred over earlier case-insensitive one")
	}

	// single case-insensitive match accepted
	got, err = selectSecurityRoleByExactName(roles[:2], "ADMINISTRATORS")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(2), *got.Id)
	}

	// multiple case-insensitive matches, none exact -> ambiguous
	got, err = selectSecurityRoleByExactName(roles[1:], "ADMINISTRATORS")
	assert.Nil(t, got)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "ambiguous")
	}

	got, err = selectSecurityRoleByExactName(roles, "Admin")
	assert.NoError(t, err)
	assert.Nil(t, got)
	got, err = selectSecurityRoleByExactName(nil, "Administrators")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestUnitSelectSecurityClaimByValueAndScheme(t *testing.T) {
	claims := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{
		testClaim(1, "other", "System"),
		testClaim(2, "Alice", "Okta"),
		testClaim(3, "alice", "System"),
	}
	got, err := selectSecurityClaimByValueAndScheme(claims, "ALICE", "System")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(3), *got.Id, "must match both value (case-insensitive) and scheme")
	}

	for _, c := range []struct{ v, s string }{{"alice", "Missing"}, {"nobody", "System"}} {
		got, err = selectSecurityClaimByValueAndScheme(claims, c.v, c.s)
		assert.NoError(t, err)
		assert.Nil(t, got)
	}
	got, err = selectSecurityClaimByValueAndScheme(nil, "alice", "System")
	assert.NoError(t, err)
	assert.Nil(t, got)

	// exact-case preferred over earlier case-insensitive match
	both := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{
		testClaim(10, "alice", "System"),
		testClaim(11, "Alice", "System"),
	}
	got, err = selectSecurityClaimByValueAndScheme(both, "Alice", "System")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(11), *got.Id)
	}

	// ambiguous: multiple case-insensitive, none exact
	got, err = selectSecurityClaimByValueAndScheme(both, "ALICE", "System")
	assert.Nil(t, got)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "ambiguous")
	}
}

func TestUnitValidatePQLStringLiteral(t *testing.T) {
	assert.NoError(t, validatePQLStringLiteral("f", "plain value"))
	assert.NoError(t, validatePQLStringLiteral("f", `back\slash-middle`))
	assert.NoError(t, validatePQLStringLiteral("f", ""))
	assert.Error(t, validatePQLStringLiteral("f", `a"b`))
	assert.Error(t, validatePQLStringLiteral("f", `ends\`))
	assert.Error(t, validatePQLStringLiteral("f", `\`))
	err := validatePQLStringLiteral("claim value", `x"`)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "claim value")
		assert.Contains(t, err.Error(), "double quote")
	}
}

func TestUnitIncludePrivateKeyOrDefault(t *testing.T) {
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Null: true}))
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Unknown: true}))
	assert.True(t, includePrivateKeyOrDefault(types.Bool{Value: true}))
	assert.False(t, includePrivateKeyOrDefault(types.Bool{Value: false}))
}

func TestUnitIncludePrivateKeyChangeRequiresReplace(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	unk := types.Bool{Unknown: true}
	cases := []struct {
		name        string
		state, plan types.Bool
		want        bool
	}{
		{"null->null", null, null, false},
		{"null->true", null, tr, false},
		{"true->null", tr, null, false},
		{"true->true", tr, tr, false},
		{"false->false", fa, fa, false},
		{"null->false", null, fa, true},
		{"true->false", tr, fa, true},
		{"false->true", fa, tr, true},
		{"false->null", fa, null, true},
		{"true->unknown", tr, unk, true},
		{"false->unknown", fa, unk, true},
		{"null->unknown", null, unk, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, includePrivateKeyChangeRequiresReplace(c.state, c.plan))
		})
	}
}

func TestUnitIncludePrivateKeyReplaceBlockedBySkipRemoval(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	unk := types.Bool{Unknown: true}
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(null, null))
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(fa, fa))
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(unk, unk))
	assert.True(t, includePrivateKeyReplaceBlockedBySkipRemoval(tr, null))
	assert.True(t, includePrivateKeyReplaceBlockedBySkipRemoval(fa, tr))
	assert.True(t, includePrivateKeyReplaceBlockedBySkipRemoval(tr, fa))
}
