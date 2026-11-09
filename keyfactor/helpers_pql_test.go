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
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
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

// Delete reads skip_removal from PRIOR STATE, so only state skip_removal = true blocks an
// include_private_key replace. Plan-only true (set in the same apply), unknown and null plan
// values must not block.
func TestUnitIncludePrivateKeyReplaceBlockedBySkipRemoval(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	unk := types.Bool{Unknown: true}
	assert.True(t, includePrivateKeyReplaceBlockedBySkipRemoval(tr), "state true blocks")
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(fa), "state false does not block")
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(null), "state null does not block")
	assert.False(t, includePrivateKeyReplaceBlockedBySkipRemoval(unk), "state unknown does not block")
}

func TestUnitExistingEntryPrivateKeyDiagnostic_MentionsCreateBeforeDestroy(t *testing.T) {
	summary, detail := existingEntryPrivateKeyDiagnostic(42, "store-1", "alias-1")
	assert.Contains(t, summary, "private key")
	assert.Contains(t, detail, "create_before_destroy")
	assert.Contains(t, detail, "'42'")
	assert.Contains(t, detail, "store-1 (alias-1)")
	assert.Contains(t, detail, "include_private_key = true")
}

func TestUnitIncludePrivateKeyDescriptionMentionsCreateBeforeDestroy(t *testing.T) {
	schema, diags := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	assert.False(t, diags.HasError())
	attr, ok := schema.Attributes["include_private_key"]
	if assert.True(t, ok) {
		assert.Contains(t, attr.Description, "create_before_destroy")
		assert.Contains(t, attr.Description, "current state")
	}
}

// Command 25.5 (kfclab, 2026-11-09): role names and (type, value, scheme) claims are unique
// case-insensitively, and the `-eq` queries match case-insensitively, so a single
// case-insensitive hit is always the same object. These tests pin the selectors' behaviour.
func TestUnitSelectSecurityRoleByExactName_CaseInsensitiveHitIsSameObject(t *testing.T) {
	roles := []kfv2.SecuritySecurityRolesSecurityRoleQueryResponse{testRole(7, "Alice")}
	got, err := selectSecurityRoleByExactName(roles, "alice")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(7), *got.Id)
	}
}

func TestUnitSelectSecurityClaimByValueAndScheme_CaseInsensitiveHitIsSameObject(t *testing.T) {
	claims := []kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse{testClaim(7, "Alice", "System")}
	got, err := selectSecurityClaimByValueAndScheme(claims, "alice", "System")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(7), *got.Id)
	}
	// A same-cased value under a different scheme is a different principal and must not match.
	got, err = selectSecurityClaimByValueAndScheme(claims, "alice", "Okta")
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

func TestUnitVerifyTemplateNames(t *testing.T) {
	templates := []api.GetTemplateResponse{{Id: 1, CommonName: "WebServer"}, {Id: 2, CommonName: "Client"}}
	ctx := context.Background()

	// Found names resolve case-insensitively on both sides, with no diagnostics.
	for _, side := range []templateNameSide{templateNameSidePlan, templateNameSideState} {
		ids, diags := verifyTemplateNames(ctx, templates, []string{"webserver", "CLIENT"}, side)
		assert.Equal(t, []int{1, 2}, ids)
		assert.Empty(t, diags)
	}

	// Missing template: plan side is an error.
	ids, diags := verifyTemplateNames(ctx, templates, []string{"WebServer", "Gone"}, templateNameSidePlan)
	assert.Equal(t, []int{1}, ids)
	assert.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityError))
	assert.Equal(t, 0, countDiagsBySeverity(diags, diag.SeverityWarning))

	// Missing template: state side is a warning, the name is skipped, and the rest still resolve.
	ids, diags = verifyTemplateNames(ctx, templates, []string{"WebServer", "Gone"}, templateNameSideState)
	assert.Equal(t, []int{1}, ids)
	assert.Equal(t, 0, countDiagsBySeverity(diags, diag.SeverityError))
	assert.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityWarning))

	// Empty name is exactly one error on both sides (no extra not-found diagnostic).
	for _, side := range []templateNameSide{templateNameSidePlan, templateNameSideState} {
		ids, diags = verifyTemplateNames(ctx, templates, []string{""}, side)
		assert.Empty(t, ids)
		assert.Equal(t, 1, countDiagsBySeverity(diags, diag.SeverityError))
		assert.Equal(t, 0, countDiagsBySeverity(diags, diag.SeverityWarning))
	}
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

	_, err := getSecurityClaimByTypeAndValueAndScheme(context.Background(), client, "OAuthSubject", "nobody", "System")
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
