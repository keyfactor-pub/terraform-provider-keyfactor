package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	kfv2 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v2"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Regression tests for the PR #228 review findings (phase-0 hardening, round 4).
// Every test here is network-free.
// ---------------------------------------------------------------------------

// ---- #3: the include_private_key replace decision lives in ModifyPlan only. ----

func deploymentForModifyPlan(ipk, skip types.Bool) CommandCertificateDeployment {
	return CommandCertificateDeployment{
		ID:                types.String{Value: "id"},
		CertificateId:     types.Int64{Value: 1},
		CertificateAlias:  types.String{Null: true},
		StoreId:           types.String{Value: "store"},
		KeyPassword:       types.String{Null: true},
		JobParameters:     types.Map{Null: true, ElemType: types.StringType},
		Overwrite:         types.Bool{Null: true},
		Redeploy:          types.Bool{Null: true},
		SkipRemoval:       skip,
		IncludePrivateKey: ipk,
	}
}

func runDeploymentModifyPlan(t *testing.T, state, plan CommandCertificateDeployment) *tfsdk.ModifyResourcePlanResponse {
	t.Helper()
	ctx := context.Background()
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	st := stateWith(t, schema, state)
	pl := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, plan).Raw}
	resp := &tfsdk.ModifyResourcePlanResponse{Plan: pl}
	resourceCommandCertificateDeployment{}.ModifyPlan(ctx, tfsdk.ModifyResourcePlanRequest{State: st, Plan: pl}, resp)
	return resp
}

func requiresReplaceIncludePrivateKey(resp *tfsdk.ModifyResourcePlanResponse) bool {
	for _, p := range resp.RequiresReplace {
		if p.Equal(path.Root("include_private_key")) {
			return true
		}
	}
	return false
}

func TestUnitDeploymentModifyPlan_IncludePrivateKeyReplaceDecision(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}
	cases := []struct {
		name        string
		state, plan types.Bool
		wantReplace bool
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := runDeploymentModifyPlan(t, deploymentForModifyPlan(c.state, null), deploymentForModifyPlan(c.plan, null))
			require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			assert.Equal(t, c.wantReplace, requiresReplaceIncludePrivateKey(resp))
		})
	}
}

// An include_private_key change still replaces the deployment, but is rejected while the PRIOR
// state has skip_removal = true; skip_removal flipping to true in the same apply is fine.
func TestUnitDeploymentModifyPlan_IncludePrivateKeyReplaceAndSkipRemoval(t *testing.T) {
	null := types.Bool{Null: true}
	tr := types.Bool{Value: true}
	fa := types.Bool{Value: false}

	resp := runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, tr), deploymentForModifyPlan(fa, tr))
	assert.True(t, resp.Diagnostics.HasError(), "state skip_removal = true blocks the replace")
	assert.True(t, requiresReplaceIncludePrivateKey(resp))

	resp = runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, fa), deploymentForModifyPlan(fa, tr))
	assert.False(t, resp.Diagnostics.HasError(), "skip_removal = true only in the plan does not block: %v", resp.Diagnostics)
	assert.True(t, requiresReplaceIncludePrivateKey(resp))

	resp = runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, tr), deploymentForModifyPlan(tr, tr))
	assert.False(t, resp.Diagnostics.HasError(), "no include_private_key change is never blocked")
	assert.False(t, requiresReplaceIncludePrivateKey(resp))

	resp = runDeploymentModifyPlan(t, deploymentForModifyPlan(tr, null), deploymentForModifyPlan(types.Bool{Unknown: true}, null))
	assert.True(t, resp.Diagnostics.HasError(), "unknown include_private_key is still rejected")
}

// The schema attribute carries no replace modifier of its own any more: ModifyPlan is the only place
// the decision is made.
func TestUnitDeploymentSchema_IncludePrivateKeyHasNoAttributePlanModifier(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	assert.Empty(t, schema.Attributes["include_private_key"].PlanModifiers)
}

// ---- #1: create_before_destroy is documented at resource level. ----

func TestUnitDeploymentResourceDescriptionMentionsCreateBeforeDestroy(t *testing.T) {
	schema, d := resourceCommandCertificateDeploymentType{}.GetSchema(context.Background())
	require.False(t, d.HasError())
	assert.Contains(t, schema.Description, "create_before_destroy")
	assert.Contains(t, schema.MarkdownDescription, "create_before_destroy")
	assert.Contains(t, schema.Description, "same certificate and alias")
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

func TestUnitClaimDataSourceRead_WarnsOnCaseInsensitiveMatch(t *testing.T) {
	const claimJSON = `[{"Id":9,"ClaimType":"OAuthSubject","ClaimValue":"Alice","Provider":{"Id":"p-1","AuthenticationScheme":"System","DisplayName":"System"}}]`

	resp, _ := oauthClaimDataSourceReadForTest(t, claimJSON, "alice")
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	warnings := resp.Diagnostics.Warnings()
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0].Detail(), `claim_value "alice" matched existing claim "Alice" case-insensitively`)

	resp, _ = oauthClaimDataSourceReadForTest(t, claimJSON, "Alice")
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	assert.Empty(t, resp.Diagnostics.Warnings(), "an exact-case match must not warn")
}

func roleCaseServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/Security/Roles") {
			_, _ = w.Write([]byte(`[{"Id":7,"Name":"Alice","Immutable":false,"PermissionSetId":"ps-1","ClaimsCount":0}]`))
			return
		}
		_, _ = w.Write([]byte(`{"Id":7,"Name":"Alice","Description":"d","Immutable":false,"PermissionSetId":"ps-1","Permissions":[],"Claims":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUnitRoleDataSourceRead_WarnsOnCaseInsensitiveMatch(t *testing.T) {
	ctx := context.Background()
	srv := roleCaseServer(t)

	for _, tc := range []struct {
		configured string
		wantWarn   bool
	}{{"alice", true}, {"Alice", false}} {
		schema, cfg := roleDataSourceConfig(t, ctx, tc.configured)
		ds := dataSourceOauthSecurityRole{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(srv)}}
		resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}
		ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: cfg}, resp)
		require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
		if !tc.wantWarn {
			assert.Empty(t, resp.Diagnostics.Warnings(), "an exact-case match must not warn")
			continue
		}
		warnings := resp.Diagnostics.Warnings()
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0].Detail(), `name "alice" matched existing role "Alice" case-insensitively`)
	}
}

func TestUnitRoleImportState_WarnsOnCaseInsensitiveMatch(t *testing.T) {
	ctx := context.Background()
	srv := roleCaseServer(t)
	schema, d := resourceOAuthSecurityRoleType{}.GetSchema(ctx)
	require.False(t, d.HasError())

	for _, tc := range []struct {
		id       string
		wantWarn bool
	}{{"alice", true}, {"Alice", false}} {
		r := resourceOAuthSecurityRole{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(srv)}}
		resp := &tfsdk.ImportResourceStateResponse{State: emptyState(ctx, schema)}
		r.ImportState(ctx, tfsdk.ImportResourceStateRequest{ID: tc.id}, resp)
		require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
		if !tc.wantWarn {
			assert.Empty(t, resp.Diagnostics.Warnings())
			continue
		}
		warnings := resp.Diagnostics.Warnings()
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0].Detail(), `"alice" matched existing role "Alice" case-insensitively`)
	}
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

func TestUnitClaimDataSourceRead_RejectsClaimOfAnotherType(t *testing.T) {
	resp, _ := oauthClaimDataSourceReadForTest(t,
		`[{"Id":9,"ClaimType":"Group","ClaimValue":"alice","Provider":{"Id":"p-1","AuthenticationScheme":"System","DisplayName":"System"}}]`,
		"alice")
	require.True(t, resp.Diagnostics.HasError(), "a claim of a different type must not satisfy the lookup")
	assert.Equal(t, "OAuth security claim not found", resp.Diagnostics.Errors()[0].Summary())
}

func TestUnitClaimDataSourceRead_KeepsConfiguredTypeWhenRemoteSpellsItNumerically(t *testing.T) {
	ctx := context.Background()
	resp, _ := oauthClaimDataSourceReadForTest(t,
		`[{"Id":9,"ClaimType":"5","ClaimValue":"alice","Provider":{"Id":"p-1","AuthenticationScheme":"System","DisplayName":"System"}}]`,
		"alice")
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	var got OAuthSecurityClaim
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.Equal(t, "OAuthSubject", got.ClaimType.Value)
}

// ---- #8: one template-name matching rule. ----

func TestUnitFindTemplateByName(t *testing.T) {
	templates := []api.GetTemplateResponse{{Id: 1, CommonName: "WebServer"}, {Id: 2, CommonName: "Client"}}
	got := findTemplateByName(templates, "webserver")
	require.NotNil(t, got)
	assert.Equal(t, 1, got.Id)
	assert.Nil(t, findTemplateByName(templates, "Gone"))
	assert.Nil(t, findTemplateByName(templates, ""), "an empty name never matches")
	assert.Nil(t, findTemplateByName(nil, "WebServer"))

	// verifyTemplateNames and partitionTemplateNamesByExistence agree on every name.
	names := []string{"webserver", "CLIENT", "Gone"}
	ids, diags := verifyTemplateNames(context.Background(), templates, names, templateNameSideState)
	kept, dropped := partitionTemplateNamesByExistence(templates, names)
	assert.Equal(t, []int{1, 2}, ids)
	assert.Equal(t, []string{"webserver", "CLIENT"}, kept)
	assert.Equal(t, []string{"Gone"}, dropped)
	assert.Len(t, diags, 1)
}
