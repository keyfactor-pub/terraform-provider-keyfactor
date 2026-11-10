package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Finding 4: a claim returned without Id, Description or ClaimType must be mapped to null
// values (or the configured value for Required attributes), not dereferenced.
func TestUnitClaimDataSourceRead_SparseClaimDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ClaimValue": "alice", "Provider": {"AuthenticationScheme": "System"}}]`))
	}))
	defer srv.Close()

	schema, d := dataSourceOAuthSecurityClaimType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	cfgState := stateWith(t, schema, OAuthSecurityClaim{
		ID:                           types.Int64{Null: true},
		Description:                  types.String{Null: true},
		ClaimType:                    types.String{Value: "OAuthSubject"},
		ClaimValue:                   types.String{Value: "Alice"},
		Provider:                     types.Object{Null: true, AttrTypes: OAuthSecurityClaimAuthenticationProviderType},
		ProviderAuthenticationScheme: types.String{Value: "System"},
	})
	ds := dataSourceOauthSecurityClaim{p: provider{sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() {
		ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: tfsdk.Config{Schema: schema, Raw: cfgState.Raw}}, resp)
	})
	require.False(t, resp.Diagnostics.HasError(), "unexpected error: %v", resp.Diagnostics)

	var got OAuthSecurityClaim
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.True(t, got.ID.Null, "missing Id must be null")
	assert.True(t, got.Description.Null, "missing Description must be null")
	assert.Equal(t, "OAuthSubject", got.ClaimType.Value, "missing ClaimType falls back to the configured value")
	assert.Equal(t, "Alice", got.ClaimValue.Value, "claim_value keeps the configured casing")
	assert.Equal(t, "System", got.ProviderAuthenticationScheme.Value)
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
