package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func roleDataSourceConfig(t *testing.T, ctx context.Context, name string) (tfsdk.Schema, tfsdk.Config) {
	t.Helper()
	schema, d := dataSourceOAuthSecurityRoleType{}.GetSchema(ctx)
	require.False(t, d.HasError())
	st := stateWith(t, schema, OAuthSecurityRole{
		ID:              types.Int64{Null: true},
		Name:            types.String{Value: name},
		Description:     types.String{Null: true},
		EmailAddress:    types.String{Null: true},
		Immutable:       types.Bool{Null: true},
		Permissions:     types.Set{Null: true, ElemType: types.StringType},
		PermissionSetId: types.String{Null: true},
	})
	return schema, tfsdk.Config{Schema: schema, Raw: st.Raw}
}

// Finding 3: when the by-ID request fails before any HTTP response exists (the SDK returns a nil
// *http.Response), the data source must report an error diagnostic, not panic.
func TestUnitRoleDataSourceRead_TransportErrorOnByIdRequestDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"Id": 7, "Name": "Admins"}]`))
			return
		}
		// Drop the connection without a response.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("hijacking not supported")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	schema, cfg := roleDataSourceConfig(t, ctx, "Admins")
	ds := dataSourceOauthSecurityRole{p: provider{sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() { ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: cfg}, resp) })
	assert.True(t, resp.Diagnostics.HasError(), "a failed by-ID read must surface as an error diagnostic")
}

// Finding 5: a role returned without an Id must produce an error, not a nil dereference.
func TestUnitRoleDataSourceRead_RoleWithoutIdIsAnError(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Name": "Admins"}]`))
	}))
	defer srv.Close()

	schema, cfg := roleDataSourceConfig(t, ctx, "Admins")
	ds := dataSourceOauthSecurityRole{p: provider{sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() { ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: cfg}, resp) })
	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics[0].Detail(), "without an ID")
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

// roleByIdServer answers the by-name query with role 7 and the by-ID read with byIdBody.
func roleByIdServer(t *testing.T, byIdBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/Security/Roles") {
			_, _ = w.Write([]byte(`[{"Id":7,"Name":"Admins"}]`))
			return
		}
		_, _ = w.Write([]byte(byIdBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// F8: the by-ID response omitting Id must be an error (a zero ID would silently alias another role),
// not a nil dereference.
func TestUnitRoleDataSourceRead_ByIdResponseWithoutIdIsAnError(t *testing.T) {
	ctx := context.Background()
	srv := roleByIdServer(t, `{"Name":"Admins","Immutable":false,"Permissions":[]}`)

	schema, cfg := roleDataSourceConfig(t, ctx, "Admins")
	ds := dataSourceOauthSecurityRole{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() { ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: cfg}, resp) })
	require.True(t, resp.Diagnostics.HasError())
	assert.Contains(t, resp.Diagnostics.Errors()[0].Detail(), "without an ID")
}

// F8: a by-ID response omitting Immutable must not be flattened to a known false.
func TestUnitRoleDataSourceRead_ByIdResponseWithoutImmutableIsNull(t *testing.T) {
	ctx := context.Background()
	srv := roleByIdServer(t, `{"Id":7,"Name":"Admins","Permissions":[]}`)

	schema, cfg := roleDataSourceConfig(t, ctx, "Admins")
	ds := dataSourceOauthSecurityRole{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(srv)}}
	resp := &tfsdk.ReadDataSourceResponse{State: emptyState(ctx, schema)}

	assert.NotPanics(t, func() { ds.Read(ctx, tfsdk.ReadDataSourceRequest{Config: cfg}, resp) })
	require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
	var got OAuthSecurityRole
	require.False(t, resp.State.Get(ctx, &got).HasError())
	assert.Equal(t, int64(7), got.ID.Value)
	assert.True(t, got.Immutable.Null, "an Immutable that Command did not send must stay null")
}
