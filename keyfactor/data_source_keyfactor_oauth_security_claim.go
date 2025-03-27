package keyfactor

import (
	"context"
	"fmt"

	kfv1 "github.com/Keyfactor/keyfactor-go-client-sdk/v3/api/keyfactor/v1"
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
				Required:    true,
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
	}, nil
}

func (r dataSourceOAuthSecurityClaimType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceSecurityRole{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceOauthSecurityClaim struct {
	p provider
}

func (r dataSourceOauthSecurityClaim) GetSecurityClaimByTypeAndValueAndScheme(ctx context.Context, claimType string, claimValue string, authenticationScheme string) (*kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse, error) {
	claimTypeEnum, err := kfv1.ParseCSSCMSCoreEnumsClaimType(claimType)
	if err != nil {
		return nil, err
	}
	api := r.p.sdkClient.V1.SecurityClaimsApi
	req := api.
		GetSecurityClaims(ctx).
		QueryString(fmt.Sprintf("((ClaimValue -eq \"%s\")) and ClaimType -eq %d", claimValue, claimTypeEnum))
	response, _, err := api.GetSecurityClaimsExecute(req)

	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, fmt.Errorf("No security claim found with claimType %s and claimValue %s", claimType, claimValue)
	}

	var result *kfv1.SecurityRoleClaimDefinitionsRoleClaimDefinitionQueryResponse

	for _, claim := range response {
		if claim.Provider != nil && claim.Provider.AuthenticationScheme.Get() != nil && *claim.Provider.AuthenticationScheme.Get() == authenticationScheme {
			result = &claim
			break
		}
	}

	if result == nil {
		return nil, fmt.Errorf("No security claim found with claimType %s and claimValue %s and authenticationScheme %s", claimType, claimValue, authenticationScheme)
	}

	return result, nil
}

func (r dataSourceOauthSecurityClaim) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	tflog.Info(ctx, "Read called on security remoteState resource")
	var state OAuthSecurityClaim

	tflog.Info(ctx, "Read called on OAuth security claim.")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	claimType := state.ClaimType.Value
	claimValue := state.ClaimValue.Value
	authenticationScheme := state.ProviderAuthenticationScheme.Value
	tflog.SetField(ctx, "claim_type", claimType)
	tflog.SetField(ctx, "claim_value", claimValue)
	tflog.SetField(ctx, "authentication_scheme", authenticationScheme)

	remoteState, err := r.GetSecurityClaimByTypeAndValueAndScheme(ctx, claimType, claimValue, authenticationScheme)
	if remoteState == nil {
		response.Diagnostics.AddError("Unknown OAuth security claim error.", fmt.Sprintf("Unable to find OAuth security claim '%s' with claimType '%s' on Keyfactor. Read failed. ", claimValue, claimType))
		return
	}

	if err != nil {
		response.Diagnostics.AddError("Unknown OAuth security claim error.", fmt.Sprintf("Unknown error while trying to import OAuth security claim '%s' with claimType '%s' on Keyfactor. Read failed. "+err.Error(), claimValue, claimType))
		return
	}

	provider := *remoteState.Provider

	var result = OAuthSecurityClaim{
		ID:          types.Int64{Value: int64(*remoteState.Id)},
		Description: types.String{Value: *remoteState.Description.Get()},
		ClaimType:   types.String{Value: *remoteState.ClaimType.Get()},
		ClaimValue:  types.String{Value: *remoteState.ClaimValue.Get()},
		Provider:    mapAuthenticationProviderType(*provider.Id, *provider.AuthenticationScheme.Get(), *provider.DisplayName.Get()),
	}

	diags = response.State.Set(ctx, result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	if response.Diagnostics.HasError() {
		return
	}
}
