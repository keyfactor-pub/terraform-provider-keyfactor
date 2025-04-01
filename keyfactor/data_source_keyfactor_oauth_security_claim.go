package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type dataSourceOAuthSecurityClaimType struct{}

func (r dataSourceOAuthSecurityClaimType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Internal ID of the role.",
			},
			"description": {
				Type:        types.StringType,
				Computed:    true,
				Description: "A string containing the description of the OAuth security claim in Keyfactor",
			},
			"claim_type": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the claim type of the OAuth security claim in Keyfactor",
			},
			"claim_value": {
				Type:        types.StringType,
				Required:    true,
				Description: "A string containing the claim value of the OAuth security claim in Keyfactor",
			},
			"provider_authentication_scheme": {
				Type:        types.StringType,
				Required:    true,
				Description: "The identity provider associated with the OAuth security claim. Used only for resource creation. Not returned by the API.",
			},
			"provider": {
				Type: types.ObjectType{
					AttrTypes: OAuthSecurityClaimAuthenticationProviderType,
				},
				Computed:    true,
				Description: "An object containing the provider of the OAuth security claim in Keyfactor",
			},
		},
		Description: "Reads an existing security claims from Keyfactor Command using the V1 `/Security/Claims` API. Compatible with Keyfactor Command versions 11+.",
	}, nil
}

func (r dataSourceOAuthSecurityClaimType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceOauthSecurityClaim{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceOauthSecurityClaim struct {
	p provider
}

func (r dataSourceOauthSecurityClaim) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	tflog.Info(ctx, "Read called on security remoteState resource")
	var state OAuthSecurityClaim

	tflog.Debug(ctx, "Read called on OAuth security claim data source.")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	claimType := state.ClaimType.Value
	claimValue := state.ClaimValue.Value
	authenticationScheme := state.ProviderAuthenticationScheme.Value
	tflog.SetField(ctx, "claim_type", claimType)

	remoteState, err := getSecurityClaimByTypeAndValueAndScheme(ctx, r.p.sdkClient, claimType, claimValue, authenticationScheme)
	if remoteState == nil {
		response.Diagnostics.AddError("Unknown OAuth security claim error.", fmt.Sprintf("Unable to find OAuth security claim '%s' with claimType '%s' for scheme '%s' on Keyfactor. Read failed. ", claimValue, claimType, authenticationScheme))
		return
	}

	if err != nil {
		response.Diagnostics.AddError("Unknown OAuth security claim error.", fmt.Sprintf("Unknown error while trying to import OAuth security claim '%s' with claimType '%s' for scheme '%s' on Keyfactor. Read failed. "+err.Error(), claimValue, claimType, authenticationScheme))
		return
	}

	tflog.Debug(ctx, "Data source was able to pull OAuth security claim from remote source")

	provider := *remoteState.Provider

	var result = OAuthSecurityClaim{
		ID:                           types.Int64{Value: int64(*remoteState.Id)},
		Description:                  types.String{Value: *remoteState.Description.Get()},
		ClaimType:                    types.String{Value: *remoteState.ClaimType.Get()},
		ClaimValue:                   types.String{Value: *remoteState.ClaimValue.Get()},
		ProviderAuthenticationScheme: types.String{Value: *provider.AuthenticationScheme.Get()},
		Provider:                     mapAuthenticationProviderType(*provider.Id, *provider.AuthenticationScheme.Get(), *provider.DisplayName.Get()),
	}

	tflog.Debug(ctx, "Saving OAuth security claim to state")

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "OAuth security claim data source read successfully.")
}
