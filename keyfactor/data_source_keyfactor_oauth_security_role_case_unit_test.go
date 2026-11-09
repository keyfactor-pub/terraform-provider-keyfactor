package keyfactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Regression: Command's role-name lookup is case-insensitive (verified against Command 25.5),
// so configuring name = "alice" can resolve role "Alice". The data source must keep the
// configured value in state; writing the remote casing makes Terraform reject the result
// ("Provider produced invalid object") because `name` is a configured attribute.
func TestUnitOAuthSecurityRoleDataSource_KeepsConfiguredNameWhenRemoteCaseDiffers(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/Security/Roles") {
			_, _ = w.Write([]byte(`[{"Id":7,"Name":"Alice","Immutable":false,"PermissionSetId":"ps-1","ClaimsCount":0}]`))
			return
		}
		_, _ = w.Write([]byte(`{"Id":7,"Name":"Alice","Description":"d","Immutable":false,"PermissionSetId":"ps-1","Permissions":[],"Claims":[]}`))
	}))
	defer server.Close()

	schema, diags := dataSourceOAuthSecurityRoleType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema: %+v", diags)
	}

	config := OAuthSecurityRole{
		ID:              types.Int64{Null: true},
		Name:            types.String{Value: "alice"},
		Description:     types.String{Null: true},
		EmailAddress:    types.String{Null: true},
		Immutable:       types.Bool{Null: true},
		Permissions:     types.Set{Null: true, ElemType: types.StringType},
		PermissionSetId: types.String{Null: true},
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("config.Set: %+v", d)
	}

	ds := dataSourceOauthSecurityRole{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(server)}}
	req := tfsdk.ReadDataSourceRequest{Config: tfsdk.Config{Schema: schema, Raw: scratch.Raw}}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}
	ds.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned errors: %+v", resp.Diagnostics)
	}
	var got OAuthSecurityRole
	if d := resp.State.Get(ctx, &got); d.HasError() {
		t.Fatalf("State.Get: %+v", d)
	}
	if got.Name.Value != "alice" {
		t.Errorf("state name = %q, want the configured %q (remote casing must not leak into a configured attribute)", got.Name.Value, "alice")
	}
	if got.ID.Value != 7 {
		t.Errorf("state id = %d, want 7", got.ID.Value)
	}
}

func oauthClaimDataSourceReadForTest(t *testing.T, claimsJSON string, claimValue string) (*tfsdk.ReadDataSourceResponse, tfsdk.Schema) {
	t.Helper()
	ctx := context.Background()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(claimsJSON))
	}))
	t.Cleanup(server.Close)

	schema, diags := dataSourceOAuthSecurityClaimType{}.GetSchema(ctx)
	if diags.HasError() {
		t.Fatalf("GetSchema: %+v", diags)
	}
	config := OAuthSecurityClaim{
		ID:                           types.Int64{Null: true},
		Description:                  types.String{Null: true},
		ClaimType:                    types.String{Value: "OAuthSubject"},
		ClaimValue:                   types.String{Value: claimValue},
		Provider:                     types.Object{Null: true, AttrTypes: OAuthSecurityClaimAuthenticationProviderType},
		ProviderAuthenticationScheme: types.String{Value: "System"},
	}
	scratch := tfsdk.Plan{Schema: schema}
	if d := scratch.Set(ctx, &config); d.HasError() {
		t.Fatalf("config.Set: %+v", d)
	}
	ds := dataSourceOauthSecurityClaim{p: provider{configured: true, sdkClient: newTemplateUpdateSDKClient(server)}}
	req := tfsdk.ReadDataSourceRequest{Config: tfsdk.Config{Schema: schema, Raw: scratch.Raw}}
	resp := &tfsdk.ReadDataSourceResponse{State: tfsdk.State{Schema: schema}}
	ds.Read(ctx, req, resp)
	return resp, schema
}

// Same case-insensitive-lookup hazard as the role data source: claim_value is configured, so the
// configured value must be kept even if Command stores a different casing.
func TestUnitOAuthSecurityClaimDataSource_KeepsConfiguredValueWhenRemoteCaseDiffers(t *testing.T) {
	ctx := context.Background()
	resp, _ := oauthClaimDataSourceReadForTest(t,
		`[{"Id":9,"Description":"d","ClaimType":"OAuthSubject","ClaimValue":"Alice","Provider":{"Id":"p-1","AuthenticationScheme":"System","DisplayName":"System"}}]`,
		"alice")
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read returned errors: %+v", resp.Diagnostics)
	}
	var got OAuthSecurityClaim
	if d := resp.State.Get(ctx, &got); d.HasError() {
		t.Fatalf("State.Get: %+v", d)
	}
	if got.ClaimValue.Value != "alice" {
		t.Errorf("state claim_value = %q, want the configured %q", got.ClaimValue.Value, "alice")
	}
}

// Not-found must surface as "OAuth security claim not found", not the old "Unknown ... import" error.
func TestUnitOAuthSecurityClaimDataSource_NotFoundMessage(t *testing.T) {
	resp, _ := oauthClaimDataSourceReadForTest(t, `[]`, "nobody")
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error for a missing claim")
	}
	errs := resp.Diagnostics.Errors()
	if errs[0].Summary() != "OAuth security claim not found" {
		t.Errorf("summary = %q, want %q", errs[0].Summary(), "OAuth security claim not found")
	}
	if strings.Contains(errs[0].Detail(), "import") {
		t.Errorf("detail should not mention import: %q", errs[0].Detail())
	}
}
