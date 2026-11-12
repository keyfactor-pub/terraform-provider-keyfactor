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

// Create relies on mapOAuthSecurityRole to reject a response without an Id: an error, no panic, no state.
func TestUnitOAuthSecurityRoleCreate_ResponseWithoutIdIsAnError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Name":"NoId","Permissions":[]}`))
	}))
	defer srv.Close()

	schema, d := resourceOAuthSecurityRoleType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	plan := tfsdk.Plan{Schema: schema, Raw: stateWith(t, schema, OAuthSecurityRole{
		ID:              types.Int64{Unknown: true},
		Name:            types.String{Value: "NoId"},
		Description:     types.String{Value: "d"},
		EmailAddress:    types.String{Null: true},
		Immutable:       types.Bool{Unknown: true},
		Permissions:     types.Set{Null: true, ElemType: types.StringType},
		PermissionSetId: types.String{Null: true},
	}).Raw}
	r := resourceOAuthSecurityRole{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.CreateResourceResponse{State: emptyState(ctx, schema)}
	require.NotPanics(t, func() { r.Create(ctx, tfsdk.CreateResourceRequest{Plan: plan}, resp) })

	require.True(t, resp.Diagnostics.HasError())
	assert.True(t, resp.State.Raw.IsNull())
}
