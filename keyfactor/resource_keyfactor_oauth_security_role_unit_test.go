package keyfactor

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
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
