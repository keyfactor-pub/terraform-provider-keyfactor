package keyfactor

import (
	"io"
	"net/http"
	"strings"
	"testing"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnitRequireSecurityRoleID(t *testing.T) {
	_, err := requireSecurityRoleID("Admins", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Admins")
	id := int32(9)
	got, err := requireSecurityRoleID("Admins", &id)
	require.NoError(t, err)
	assert.Equal(t, int32(9), got)
}

func TestUnitReadErrorResponseBody_NilSafe(t *testing.T) {
	assert.Equal(t, "", readErrorResponseBody(nil))
	assert.Equal(t, "", readErrorResponseBody(&http.Response{}))
	assert.Equal(t, "boom", readErrorResponseBody(&http.Response{Body: io.NopCloser(strings.NewReader("boom"))}))
}

func TestUnitPickPreferExactCase(t *testing.T) {
	type item struct{ key string }
	cand := func(i *item) (string, bool) { return i.key, i.key != "skip" }

	items := []item{{"alice"}, {"Alice"}, {"ALICE"}}
	got, folded, n := pickPreferExactCase(items, "Alice", cand)
	require.NotNil(t, got)
	assert.Equal(t, "Alice", got.key, "exact case wins over earlier case-insensitive hits")
	assert.False(t, folded, "an exact-case match is not flagged")
	assert.Equal(t, 0, n)

	got, folded, n = pickPreferExactCase([]item{{"alice"}}, "ALICE", cand)
	require.NotNil(t, got)
	assert.True(t, folded, "a case-insensitive-only match is flagged")
	assert.Equal(t, 0, n, "a returned item is never ambiguous")

	got, folded, n = pickPreferExactCase([]item{{"alice"}, {"aLiCe"}}, "ALICE", cand)
	assert.Nil(t, got)
	assert.False(t, folded)
	assert.Equal(t, 2, n, "multiple case-insensitive hits with no exact match are ambiguous")

	got, folded, n = pickPreferExactCase([]item{{"skip"}, {"bob"}}, "skip", cand)
	assert.Nil(t, got, "ineligible items are ignored")
	assert.False(t, folded)
	assert.Equal(t, 0, n)
}

// ---- #5: case-insensitive fallback surfaces a warning. ----

func TestUnitCaseInsensitiveMatchWarning_Text(t *testing.T) {
	summary, detail := caseInsensitiveMatchWarning("claim_value", "claim", "alice", "Alice")
	assert.Contains(t, summary, "case-insensitively")
	assert.Contains(t, detail, `claim_value "alice" matched existing claim "Alice" case-insensitively`)
}

func TestUnitSelectSecurityRoleByExactName_ReportsCaseInsensitiveFallback(t *testing.T) {
	roles := testRoles("Alice")
	got, folded, err := selectSecurityRoleByExactName(roles, "alice")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, folded, "case-insensitive-only match must be flagged")

	got, folded, err = selectSecurityRoleByExactName(roles, "Alice")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.False(t, folded, "exact-case match must not be flagged")

	got, folded, err = selectSecurityRoleByExactName(roles, "bob")
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.False(t, folded)
}

func TestUnitSelectSecurityClaimByValueAndScheme_ReportsCaseInsensitiveFallback(t *testing.T) {
	claims := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{testClaim(7, "Alice", "System")}
	got, folded, err := selectSecurityClaimByValueAndScheme(claims, "alice", "System", "OAuthSubject")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, folded)

	got, folded, err = selectSecurityClaimByValueAndScheme(claims, "Alice", "System", "OAuthSubject")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.False(t, folded)
}

func testRoles(names ...string) []kfv2.SecuritySecurityRolesSecurityRoleQueryResponse {
	out := make([]kfv2.SecuritySecurityRolesSecurityRoleQueryResponse, 0, len(names))
	for i, n := range names {
		out = append(out, testRole(int32(i+1), n))
	}
	return out
}

// ---- #6: claim_type / provider_authentication_scheme keep the configured values, and the selector
// verifies the remote claim type. ----

func TestUnitMapOAuthSecurityClaimQueryResult_KeepsConfiguredTypeAndScheme(t *testing.T) {
	remote := testClaim(9, "Alice", "okta")
	remoteType := "5" // the numeric spelling of OAuthSubject
	remote.ClaimType.Set(&remoteType)
	providerName := "Okta"
	remote.Provider.DisplayName.Set(&providerName)

	configured := OAuthSecurityClaim{
		ClaimType:                    types.String{Value: "OAuthSubject"},
		ClaimValue:                   types.String{Value: "alice"},
		ProviderAuthenticationScheme: types.String{Value: "Okta"},
	}
	got := mapOAuthSecurityClaimQueryResult(&remote, configured)
	assert.Equal(t, "OAuthSubject", got.ClaimType.Value, "claim_type keeps the configured value")
	assert.Equal(t, "alice", got.ClaimValue.Value)
	assert.Equal(t, "Okta", got.ProviderAuthenticationScheme.Value, "scheme keeps the configured value")
	assert.Equal(t, int64(9), got.ID.Value)
	assert.False(t, got.Provider.Null, "the provider object still reflects the remote claim")
}

func TestUnitSecurityClaimTypeMatches(t *testing.T) {
	s := func(v string) *string { return &v }
	assert.True(t, securityClaimTypeMatches(s("OAuthSubject"), "OAuthSubject"), "name")
	assert.True(t, securityClaimTypeMatches(s("oauthsubject"), "OAuthSubject"), "name is case-insensitive")
	assert.True(t, securityClaimTypeMatches(s("5"), "OAuthSubject"), "enum number as text")
	assert.True(t, securityClaimTypeMatches(s(" 5 "), "OAuthSubject"), "number is trimmed")
	assert.True(t, securityClaimTypeMatches(nil, "OAuthSubject"), "absent type cannot be checked and is accepted")
	assert.False(t, securityClaimTypeMatches(s("Group"), "OAuthSubject"), "other name")
	assert.False(t, securityClaimTypeMatches(s("1"), "OAuthSubject"), "other number")
	assert.False(t, securityClaimTypeMatches(s("OAuthSubjectX"), "OAuthSubject"))
	assert.False(t, securityClaimTypeMatches(s("5"), "NotAType"), "unparseable requested type never matches")
}

func TestUnitSelectSecurityClaimByValueAndScheme_VerifiesClaimType(t *testing.T) {
	mk := func(id int32, typ string) kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse {
		c := testClaim(id, "alice", "System")
		c.ClaimType.Set(&typ)
		return c
	}
	claims := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{mk(1, "Group"), mk(2, "OAuthSubject")}
	got, _, err := selectSecurityClaimByValueAndScheme(claims, "alice", "System", "OAuthSubject")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int32(2), *got.Id, "the claim of the requested type is selected")

	got, _, err = selectSecurityClaimByValueAndScheme(claims[:1], "alice", "System", "OAuthSubject")
	require.NoError(t, err)
	assert.Nil(t, got, "a claim of another type is never returned")

	numeric := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{mk(3, "1"), mk(4, "5")}
	got, _, err = selectSecurityClaimByValueAndScheme(numeric, "alice", "System", "OAuthSubject")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int32(4), *got.Id, "numeric claim types are compared by enum value")
}
