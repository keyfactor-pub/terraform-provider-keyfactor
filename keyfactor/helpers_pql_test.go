package keyfactor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	_, _, err := getSecurityRoleByName(context.Background(), nil, `x") or (Name -ne "`)
	if !assert.Error(t, err) {
		return
	}
	assert.Contains(t, err.Error(), "double quote")
}

func TestUnitGetSecurityClaimByTypeAndValueAndScheme_RejectsQuote(t *testing.T) {
	_, _, err := getSecurityClaimByTypeAndValueAndScheme(context.Background(), nil, "OAuthSubject", `a" or ClaimValue -ne "b`, "System")
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
	got, _, err := selectSecurityRoleByExactName(roles, "Administrators")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(3), *got.Id, "exact-case match preferred over earlier case-insensitive one")
	}

	// single case-insensitive match accepted
	got, _, err = selectSecurityRoleByExactName(roles[:2], "ADMINISTRATORS")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(2), *got.Id)
	}

	// multiple case-insensitive matches, none exact -> ambiguous
	got, _, err = selectSecurityRoleByExactName(roles[1:], "ADMINISTRATORS")
	assert.Nil(t, got)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "ambiguous")
	}

	got, _, err = selectSecurityRoleByExactName(roles, "Admin")
	assert.NoError(t, err)
	assert.Nil(t, got)
	got, _, err = selectSecurityRoleByExactName(nil, "Administrators")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestUnitSelectSecurityClaimByValueAndScheme(t *testing.T) {
	claims := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{
		testClaim(1, "other", "System"),
		testClaim(2, "Alice", "Okta"),
		testClaim(3, "alice", "System"),
	}
	got, _, err := selectSecurityClaimByValueAndScheme(claims, "ALICE", "System", "OAuthSubject")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(3), *got.Id, "must match both value (case-insensitive) and scheme")
	}

	for _, c := range []struct{ v, s string }{{"alice", "Missing"}, {"nobody", "System"}} {
		got, _, err = selectSecurityClaimByValueAndScheme(claims, c.v, c.s, "OAuthSubject")
		assert.NoError(t, err)
		assert.Nil(t, got)
	}
	got, _, err = selectSecurityClaimByValueAndScheme(nil, "alice", "System", "OAuthSubject")
	assert.NoError(t, err)
	assert.Nil(t, got)

	// exact-case preferred over earlier case-insensitive match
	both := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{
		testClaim(10, "alice", "System"),
		testClaim(11, "Alice", "System"),
	}
	got, _, err = selectSecurityClaimByValueAndScheme(both, "Alice", "System", "OAuthSubject")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(11), *got.Id)
	}

	// ambiguous: multiple case-insensitive, none exact
	got, _, err = selectSecurityClaimByValueAndScheme(both, "ALICE", "System", "OAuthSubject")
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

// Command 25.5 (kfclab, 2026-11-09): role names and (type, value, scheme) claims are unique
// case-insensitively, and the `-eq` queries match case-insensitively, so a single
// case-insensitive hit is always the same object. These tests pin the selectors' behaviour.
func TestUnitSelectSecurityRoleByExactName_CaseInsensitiveHitIsSameObject(t *testing.T) {
	roles := []kfv2.SecuritySecurityRolesSecurityRoleQueryResponse{testRole(7, "Alice")}
	got, _, err := selectSecurityRoleByExactName(roles, "alice")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(7), *got.Id)
	}
}

func TestUnitSelectSecurityClaimByValueAndScheme_CaseInsensitiveHitIsSameObject(t *testing.T) {
	claims := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{testClaim(7, "Alice", "System")}
	got, _, err := selectSecurityClaimByValueAndScheme(claims, "alice", "System", "OAuthSubject")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(7), *got.Id)
	}
	// A same-cased value under a different scheme is a different principal and must not match.
	got, _, err = selectSecurityClaimByValueAndScheme(claims, "alice", "Okta", "OAuthSubject")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestUnitRoleDataSourceStateName_KeepsConfiguredValue(t *testing.T) {
	// Remote casing differs from config: the configured value must be kept.
	got := roleDataSourceStateName(types.String{Value: "alice"}, types.String{Value: "Alice"})
	assert.Equal(t, "alice", got.Value)
	assert.False(t, got.Null)
	// No configured value (defensive): fall back to remote.
	got = roleDataSourceStateName(types.String{Null: true}, types.String{Value: "Alice"})
	assert.Equal(t, "Alice", got.Value)
}

func countDiagsBySeverity(diags []diag.Diagnostic, sev diag.Severity) int {
	n := 0
	for _, d := range diags {
		if d.Severity() == sev {
			n++
		}
	}
	return n
}

func TestUnitSecurityClaimNotFoundSentinel(t *testing.T) {
	// The not-found error is wrapped so callers can use errors.Is, and keeps context.
	err := fmt.Errorf("%w: claimType %s and claimValue %s", errSecurityClaimNotFound, "OAuthSubject", "alice")
	assert.True(t, errors.Is(err, errSecurityClaimNotFound))
	assert.False(t, errors.Is(errors.New("boom"), errSecurityClaimNotFound))

	summary, detail := securityClaimDataSourceReadError(err, "OAuthSubject", "alice", "System")
	assert.Equal(t, "OAuth security claim not found", summary)
	assert.Contains(t, detail, "alice")

	summary, detail = securityClaimDataSourceReadError(errors.New("connection refused"), "OAuthSubject", "alice", "System")
	assert.Equal(t, "Error reading OAuth security claim", summary)
	assert.NotContains(t, detail, "import")
	assert.Contains(t, detail, "connection refused")
}

// With an empty claim list the real lookup path returns the sentinel; drive it through a stub
// server to prove the production function (not just the helper) wraps it.
func TestUnitGetSecurityClaimByTypeAndValueAndScheme_NotFoundIsSentinel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	client := newTemplateUpdateSDKClient(srv)

	_, _, err := getSecurityClaimByTypeAndValueAndScheme(context.Background(), client, "OAuthSubject", "nobody", "System")
	if assert.Error(t, err) {
		assert.True(t, errors.Is(err, errSecurityClaimNotFound), "got: %v", err)
	}
}

// The validator runs before the client is touched, so a nil client proves no query is issued.
func TestUnitSearchCertificatesForOrphanRecovery_IncludesValidatorReason(t *testing.T) {
	_, err := searchCertificatesForOrphanRecovery(context.Background(), nil, `host\`)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "backslash")
		assert.NotContains(t, err.Error(), "double-quote")
		assert.Contains(t, err.Error(), "terraform import")
	}
	_, err = searchCertificatesForOrphanRecovery(context.Background(), nil, `ho"st`)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "double quote")
		assert.Contains(t, err.Error(), "terraform import")
	}
}
