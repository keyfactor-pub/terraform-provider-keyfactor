package keyfactor

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client-sdk/v3"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var stderr = os.Stderr

func New() tfsdk.Provider {
	return &provider{}
}

type provider struct {
	configured bool
	client     *api.Client
	sdkClient  *keyfactor.APIClient
}

const (
	EnvVarUsage              = "This can also be set via the `%s` environment variable."
	DefaultValMsg            = "Default value is `%v`."
	InvalidProviderConfigErr = "invalid provider configuration"
)

var (
	PFXPasswordLength       int
	PFXPasswordUpperCases   int
	PFXPasswordSpecialChars int
	PFXPasswordDigits       int
	Version                 = "2.2.0"
)

// GetSchema - Defines provider schema
func (p *provider) GetSchema(ctx context.Context) (tfsdk.Schema, diag.Diagnostics) {
	tflog.Info(ctx, fmt.Sprintf("Starting Keyfactor terraform provider version %s", Version))
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"pfx_password_length": {
				Type:     types.NumberType,
				Optional: true,
				Description: fmt.Sprintf(
					"The length of password to use when generating a PFX. "+
						DefaultValMsg, DEFAULT_PFX_PASSWORD_LEN,
				),
			},
			"pfx_password_max_special_chars": {
				Type:     types.NumberType,
				Optional: true,
				Description: fmt.Sprintf(
					"The maximum number of to use when generating a PFX password. "+
						DefaultValMsg, DEFAULT_PFX_PASSWORD_SPECIAL_CHAR_COUNT,
				),
			},
			"pfx_password_min_digits": {
				Type:     types.NumberType,
				Optional: true,
				Description: fmt.Sprintf(
					"The minimum number of digits to use when generating a PFX password. "+
						DefaultValMsg, DEFAULT_PFX_PASSWORD_NUMBER_COUNT,
				),
			},
			"pfx_password_min_uppercases": {
				Type:     types.NumberType,
				Optional: true,
				Description: fmt.Sprintf(
					"The minimum number of uppercase letters to use when generating a PFX password. "+
						DefaultValMsg, DEFAULT_PFX_PASSWORD_UPPER_COUNT,
				),
			},
			"hostname": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Hostname of Keyfactor Command instance. Ex: keyfactor.examplecompany.com. "+
						EnvVarUsage, auth_providers.EnvKeyfactorHostName,
				),
			},
			"command_ca_certificate": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Path to CA certificate to use when connecting to the Keyfactor Command API in PEM"+
						" format."+EnvVarUsage, auth_providers.EnvKeyfactorCACert,
				),
			},
			"auth_ca_certificate": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Path to CA certificate to use when connecting to a Keyfactor Command identity provider in PEM"+
						" format."+EnvVarUsage, auth_providers.EnvKeyfactorCACert,
				),
			},
			"api_path": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Path to Keyfactor Command API."+DefaultValMsg+EnvVarUsage,
					auth_providers.DefaultCommandAPIPath, auth_providers.EnvKeyfactorAPIPath,
				),
			},
			"username": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Username of Keyfactor Command service account. "+
						EnvVarUsage, auth_providers.EnvKeyfactorUsername,
				),
			},
			"password": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf(
					"Password of Keyfactor Command service account. "+
						EnvVarUsage, auth_providers.EnvKeyfactorPassword,
				),
			},
			"appkey": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: "Application key provisioned by Keyfactor Command instance." +
					"This can also be set via the `KEYFACTOR_APPKEY` environment variable.",
			},
			"domain": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Domain that Keyfactor Command instance is hosted on. "+
						EnvVarUsage, auth_providers.EnvKeyfactorDomain,
				),
			},
			"token_url": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"OAuth token URL for Keyfactor Command instance. "+
						EnvVarUsage, auth_providers.EnvKeyfactorAuthTokenURL,
				),
			},
			"client_id": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Client ID for OAuth authentication. "+EnvVarUsage, auth_providers.EnvKeyfactorClientID,
				),
			},
			"client_secret": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf(
					"Client secret for OAuth authentication. "+EnvVarUsage, auth_providers.EnvKeyfactorClientSecret,
				),
			},
			"access_token": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf(
					"Access token for OAuth authentication. "+EnvVarUsage, auth_providers.EnvKeyfactorAccessToken,
				),
			},
			"scopes": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"A list of comma separated OAuth scopes to request when authenticating. "+
						EnvVarUsage, auth_providers.EnvKeyfactorAuthScopes,
				),
			},
			"audience": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"OAuth audience to request when authenticating. "+
						EnvVarUsage, auth_providers.EnvKeyfactorAuthAudience,
				),
			},
			"request_timeout": {
				Type:     types.Int64Type,
				Optional: true,
				Description: fmt.Sprintf(
					"Global timeout for HTTP requests to Keyfactor Command instance. "+EnvVarUsage+DefaultValMsg,
					auth_providers.EnvKeyfactorClientTimeout, auth_providers.DefaultClientTimeout,
				),
			},
			"skip_tls_verify": {
				Type:     types.BoolType,
				Optional: true,
				Description: fmt.Sprintf(
					"Skip TLS verification when connecting to Keyfactor Command API and identity provider."+
						DefaultValMsg+EnvVarUsage, false, auth_providers.EnvKeyfactorSkipVerify,
				),
			},
		},
		MarkdownDescription: `
## Overview

The Terraform provider for Keyfactor Command enables management of Keyfactor Command resources with HashiCorp Terraform.
Below are currently supported resources:

| Command Resource  | Keyfactor Command Doc                                                                                                              | Terraform Resource                                                                                                                               |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Certificate       | [Certificate](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/Certificates.htm)                     | [keyfactor_certificate](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate)                       |
| Certificate Store | [Certificate Store](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/CertificateStores.htm)          | [keyfactor_certificate_store](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_store)           |
| Orchestration Job | [Orchestration Job](https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/OrchestratorJobsPOSTCustom.htm) | [keyfactor_certificate_deployment](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_deployment) |

## Support

In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. Keyfactor Community
software is open-source and community-supported, meaning that **no SLA** is applicable. 
This means customers can report Bugs, Feature Requests, 
Documentation amendment or questions as well as requests for customer
information required for setup that needs Keyfactor access to obtain. Such requests do not follow normal SLA commitments
for response or resolution. If you have a support issue, please open a support ticket via the Keyfactor Support Portal
at https://support.keyfactor.com/ and Keyfactor will address issues as resources become available.

## Compatibility

| Keyfactor Command Version | Terraform Provider Version |
|---------------------------|----------------------------|
| 12.x                      | 2.2.x                      |
| 11.x                      | 2.2.x                      |
| 10.x                      | 2.0.x                      |
| 9.x                       | 1.0.x                      |
`,
		Description: "The Keyfactor Command provider allows you to authenticate to Keyfactor Command using a username" +
			" and password, or an OAuth credentials.",
	}, nil
}

// Provider schema struct
type providerData struct {
	Username             types.String `tfsdk:"username"`
	Hostname             types.String `tfsdk:"hostname"`
	CommandCACertificate types.String `tfsdk:"command_ca_certificate"`
	AuthCACertificate    types.String `tfsdk:"auth_ca_certificate"`
	Password             types.String `tfsdk:"password"`
	ApiKey               types.String `tfsdk:"appkey"`
	ApiPath              types.String `tfsdk:"api_path"`
	Domain               types.String `tfsdk:"domain"`
	TokenURL             types.String `tfsdk:"token_url"`
	ClientID             types.String `tfsdk:"client_id"`
	ClientSecret         types.String `tfsdk:"client_secret"`
	AccessToken          types.String `tfsdk:"access_token"`
	Scopes               types.String `tfsdk:"scopes"`
	Audience             types.String `tfsdk:"audience"`
	RequestTimeout       types.Int64  `tfsdk:"request_timeout"`
	SkipTLSVerify        types.Bool   `tfsdk:"skip_tls_verify"`
	PFXPasswordLength    types.Number `tfsdk:"pfx_password_length"`
	PFXPasswordUppers    types.Number `tfsdk:"pfx_password_min_uppercases"`
	PFXPasswordNumbers   types.Number `tfsdk:"pfx_password_min_digits"`
	PFXPasswordSpecials  types.Number `tfsdk:"pfx_password_max_special_chars"`
}

func (p *provider) getServerConfig(c *providerData, ctx context.Context) (*auth_providers.Server, diag.Diagnostics) {

	LogFunctionEntry(ctx, "getServerConfig")
	oAuthNoParamsConfig := &auth_providers.CommandConfigOauth{}
	basicAuthNoParamsConfig := &auth_providers.CommandAuthConfigBasic{}
	d := diag.Diagnostics{}

	// Core provider config
	tflog.Debug(ctx, "Resolving command hostname from environment variables")
	hostname, hOk := os.LookupEnv(auth_providers.EnvKeyfactorHostName)
	if !hOk || c.Hostname.Value != "" {
		tflog.Debug(ctx, "Using hostname from provider configuration")
		hostname = c.Hostname.Value
		hOk = true
	}
	ctx = tflog.SetField(ctx, "hostname", hostname)

	tflog.Debug(ctx, "Resolving API path from environment variables")
	apiPath, aOk := os.LookupEnv(auth_providers.EnvKeyfactorAPIPath)
	if !aOk || c.ApiPath.Value != "" {
		tflog.Debug(ctx, "Using API path from provider configuration")
		apiPath = c.ApiPath.Value
	}
	ctx = tflog.SetField(ctx, "api_path", apiPath)

	tflog.Debug(ctx, "Resolving TLS skip verify from environment variables")
	skipVerify, svOk := os.LookupEnv(auth_providers.EnvKeyfactorSkipVerify)
	var skipVerifyBool bool
	if c.SkipTLSVerify.Value {
		tflog.Debug(ctx, "Using TLS skip verify from provider configuration")
		skipVerifyBool = true
	} else if svOk {
		//convert to bool
		tflog.Debug(ctx, "Using TLS skip verify from environment variables")
		skipVerify = strings.ToLower(skipVerify)
		skipVerifyBool = skipVerify == "true" || skipVerify == "1" || skipVerify == "yes" || skipVerify == "y" || skipVerify == "t"
	}
	ctx = tflog.SetField(ctx, "skip_verify", skipVerify)

	tflog.Debug(ctx, "Resolving command client timeout from environment variables")
	clientTimeoutStr, tOk := os.LookupEnv(auth_providers.EnvKeyfactorClientTimeout)
	var clientTimeout int64
	if !tOk || (c.RequestTimeout.Value > 0) {
		tflog.Debug(ctx, "Using client timeout from provider configuration")
		clientTimeout = c.RequestTimeout.Value
	} else if tOk {
		tflog.Debug(ctx, "Using client timeout from environment variables")
		clientTimeout, _ = strconv.ParseInt(clientTimeoutStr, 10, 64)
	} else {
		tflog.Warn(
			ctx, fmt.Sprintf(
				"invalid value for `client_timeout` using default of %d",
				auth_providers.DefaultClientTimeout,
			),
		)
		clientTimeout = auth_providers.DefaultClientTimeout
	}
	ctx = tflog.SetField(ctx, "client_timeout", clientTimeoutStr)

	tflog.Debug(ctx, "Resolving CA cert path from environment variables")
	caCert, caOk := os.LookupEnv(auth_providers.EnvKeyfactorCACert)
	if !caOk || c.CommandCACertificate.Value != "" {
		tflog.Debug(ctx, "Using CA cert from provider configuration")
		caCert = c.CommandCACertificate.Value
	}
	ctx = tflog.SetField(ctx, "command_ca_certificate", caCert)

	// Basic auth provider config
	tflog.Debug(ctx, "Resolving username from environment variables")
	username, uOk := os.LookupEnv(auth_providers.EnvKeyfactorUsername)
	if !uOk || c.Username.Value != "" {
		tflog.Debug(ctx, "Using username from provider configuration")
		username = c.Username.Value
		if username != "" {
			uOk = true
		}
	}
	ctx = tflog.SetField(ctx, "username", username)

	tflog.Debug(ctx, "Resolving password from environment variables")
	password, pOk := os.LookupEnv(auth_providers.EnvKeyfactorPassword)
	if !pOk || c.Password.Value != "" {
		tflog.Debug(ctx, "Using password from provider configuration")
		password = c.Password.Value

	}
	ctx = tflog.SetField(ctx, "password", password)
	if password != "" {
		ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "password", password)
		pOk = true
	}

	tflog.Debug(ctx, "Resolving domain path from environment variables")
	domain, dOk := os.LookupEnv(auth_providers.EnvKeyfactorDomain)
	if !dOk || c.Domain.Value != "" {
		tflog.Debug(ctx, "Using domain from provider configuration")
		domain = c.Domain.Value
		if domain != "" {
			dOk = true
		}
	}
	ctx = tflog.SetField(ctx, "domain", domain)

	//oAuth auth provider config
	tflog.Debug(ctx, "Resolving oauth clientID from environment variables")
	clientId, cOk := os.LookupEnv(auth_providers.EnvKeyfactorClientID)
	if !cOk || c.ClientID.Value != "" {
		tflog.Debug(ctx, "Using clientID from provider configuration")
		clientId = c.ClientID.Value
		if clientId != "" {
			cOk = true
		}
	}
	ctx = tflog.SetField(ctx, "client_id", clientId)

	tflog.Debug(ctx, "Resolving oauth clientSecret from environment variables")
	clientSecret, csOk := os.LookupEnv(auth_providers.EnvKeyfactorClientSecret)
	if !csOk || c.ClientSecret.Value != "" {
		tflog.Debug(ctx, "Using clientSecret from provider configuration")
		clientSecret = c.ClientSecret.Value
	}
	ctx = tflog.SetField(ctx, "client_secret", clientSecret)
	if clientSecret != "" {
		ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "client_secret", clientSecret)
		csOk = true
	}

	tflog.Debug(ctx, "Resolving oauth tokenURL from environment variables")
	tokenUrl, tOk := os.LookupEnv(auth_providers.EnvKeyfactorAuthTokenURL)
	if !tOk || c.TokenURL.Value != "" {
		tflog.Debug(ctx, "Using tokenURL from provider configuration")
		tokenUrl = c.TokenURL.Value
		if tokenUrl != "" {
			tOk = true
		}
	}
	ctx = tflog.SetField(ctx, "token_url", tokenUrl)

	tflog.Debug(ctx, "Resolving oauth bearer token from environment variables")
	accessToken, atOk := os.LookupEnv(auth_providers.EnvKeyfactorAccessToken)
	if !atOk || c.AccessToken.Value != "" {
		tflog.Debug(ctx, "Using access token from provider configuration")
		accessToken = c.AccessToken.Value
	}
	ctx = tflog.SetField(ctx, "access_token", accessToken)
	if accessToken != "" {
		ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "access_token", accessToken)
		atOk = true
	}

	tflog.Debug(ctx, "Resolving oauth scopes from environment variables")
	scopesCsvStr, scOk := os.LookupEnv(auth_providers.EnvKeyfactorAuthScopes)
	if !scOk || c.Scopes.Value != "" {
		tflog.Debug(ctx, "Using scopes from provider configuration")
		scopesCsvStr = c.Scopes.Value
	}
	scopesList := strings.Split(scopesCsvStr, ",")
	//check if slice is list of empty ""
	if len(scopesList) == 1 && scopesList[0] == "" {
		scopesList = []string{}
	}

	audience, audOk := os.LookupEnv(auth_providers.EnvKeyfactorAuthAudience)
	if !audOk || c.Audience.Value != "" {
		tflog.Debug(ctx, "Using audience from provider configuration")
		audience = c.Audience.Value
	}

	isBasicAuth := uOk && pOk
	ctx = tflog.SetField(ctx, "is_basic_auth", isBasicAuth)
	isOAuth := (cOk && csOk && tOk) || atOk
	ctx = tflog.SetField(ctx, "is_oauth", isOAuth)

	tflog.Debug(ctx, "Beginning authentication")
	if isBasicAuth {
		LogFunctionCall(ctx, "basicAuthNoParamsConfig.Authenticate")
		basicAuthNoParamsConfig.WithCommandHostName(hostname).
			WithCommandAPIPath(apiPath).
			WithSkipVerify(skipVerifyBool).
			WithCommandCACert(caCert).
			WithClientTimeout(int(clientTimeout))
		bErr := basicAuthNoParamsConfig.
			WithUsername(username).
			WithPassword(password).
			WithDomain(domain).
			Authenticate()
		LogFunctionReturned(ctx, "basicAuthNoParamsConfig.Authenticate")

		if bErr != nil {
			errMsg := fmt.Sprintf("unable to authenticate with provided basic auth credentials: %s" + bErr.Error())
			tflog.Error(ctx, errMsg)
			d.AddError("basic auth authentication error", errMsg)
			return nil, d
		}
		LogFunctionExit(ctx, "getServerConfigFromEnv()")
		return basicAuthNoParamsConfig.GetServerConfig(), d
	} else if isOAuth {
		LogFunctionCall(ctx, "oAuthNoParamsConfig.Authenticate()")
		_ = oAuthNoParamsConfig.CommandAuthConfig.
			WithCommandHostName(hostname).
			WithCommandAPIPath(apiPath).
			WithSkipVerify(skipVerifyBool).
			WithCommandCACert(caCert).
			WithClientTimeout(int(clientTimeout))
		oErr := oAuthNoParamsConfig.
			WithClientId(clientId).
			WithClientSecret(clientSecret).
			WithScopes(scopesList).
			WithAudience(audience).
			WithTokenUrl(tokenUrl).
			WithAccessToken(accessToken).
			Authenticate()
		LogFunctionReturned(ctx, "oAuthNoParamsConfig.Authenticate()")
		if oErr != nil {
			oErrMsg := fmt.Sprintf("unable to authenticate with provided OAuth auth credentials: %s", oErr.Error())
			tflog.Error(ctx, oErrMsg)
			d.AddError("oauth authentication error: "+oErr.Error(), oErrMsg)
			return nil, d
		}

		LogFunctionExit(ctx, "getServerConfigFromEnv()")
		oAuthNoParamsConfig.GetHttpClient()
		return oAuthNoParamsConfig.GetServerConfig(), d
	}

	cErrMsg := "unable to authenticate with provided credentials"
	tflog.Error(ctx, cErrMsg)
	d.AddError("client configuration error", cErrMsg)
	LogFunctionExit(ctx, "getServerConfigFromEnv()")
	return nil, d

}

func parsePasswordFormatField(field types.Number, defaultValue int) int {
	digitStr := field.String()
	count, err := strconv.Atoi(digitStr)
	if err != nil {
		return defaultValue
	}
	return count
}

func (p *provider) Configure(
	ctx context.Context,
	req tfsdk.ConfigureProviderRequest,
	resp *tfsdk.ConfigureProviderResponse,
) {
	// Retrieve provider data from configuration
	var config providerData

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "validating provider auth configuration")
	serverConfig, confDiags := p.getServerConfig(&config, ctx)
	resp.Diagnostics.Append(confDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, "provider configuration is valid")

	PFXPasswordLength = parsePasswordFormatField(config.PFXPasswordLength, DEFAULT_PFX_PASSWORD_LEN)
	PFXPasswordDigits = parsePasswordFormatField(config.PFXPasswordNumbers, DEFAULT_PFX_PASSWORD_NUMBER_COUNT)
	PFXPasswordSpecialChars = parsePasswordFormatField(
		config.PFXPasswordSpecials,
		DEFAULT_PFX_PASSWORD_SPECIAL_CHAR_COUNT,
	)
	PFXPasswordUpperCases = parsePasswordFormatField(config.PFXPasswordUppers, DEFAULT_PFX_PASSWORD_UPPER_COUNT)

	// User must provide a user to the provider
	connected := false
	connectionRetries := 0
	for !connected && connectionRetries < 5 {
		c, err := api.NewKeyfactorClient(serverConfig, &ctx)

		if err != nil {
			if connectionRetries == 4 {
				resp.Diagnostics.AddError(
					"Client error.",
					"Unable to create client connection to Keyfactor Command:\n\n"+err.Error(),
				)
				return
			}
			connectionRetries++
			// Sleep for 5 seconds before retrying
			time.Sleep(5 * time.Second)
			continue
		}
		connected = true
		p.client = c
		continue
	}

	connected = false
	connectionRetries = 0
	for !connected && connectionRetries < 5 {
		c, err := keyfactor.NewAPIClient(serverConfig)

		if err != nil {
			if connectionRetries == 4 {
				resp.Diagnostics.AddError(
					"Client error.",
					"Unable to create client connection to Keyfactor Command (SDK client):\n\n"+err.Error(),
				)
				return
			}
			connectionRetries++
			// Sleep for 5 seconds before retrying
			time.Sleep(5 * time.Second)
			continue
		}
		connected = true
		p.sdkClient = c
		p.configured = true
		continue
	}
}

// GetResources - Defines provider resources
func (p *provider) GetResources(_ context.Context) (map[string]tfsdk.ResourceType, diag.Diagnostics) {
	return map[string]tfsdk.ResourceType{
		"keyfactor_identity":               resourceSecurityIdentityType{},
		"keyfactor_certificate":            resourceCommandCertificateType{},
		"keyfactor_certificate_store":      resourceCertificateStoreType{},
		"keyfactor_certificate_deployment": resourceCommandCertificateDeploymentType{},
		"keyfactor_oauth_security_claim":   resourceOAuthSecurityClaimType{},
		"keyfactor_role":                   resourceSecurityRoleType{},
		"keyfactor_template_role_binding":  resourceCertificateTemplateRoleBindingType{},
	}, nil
}

// GetDataSources - Defines provider data sources
func (p *provider) GetDataSources(_ context.Context) (map[string]tfsdk.DataSourceType, diag.Diagnostics) {
	return map[string]tfsdk.DataSourceType{
		"keyfactor_agent":                dataSourceAgentType{},
		"keyfactor_certificate":          dataSourceCertificateType{},
		"keyfactor_certificate_store":    dataSourceCertificateStoreType{},
		"keyfactor_certificate_template": dataSourceCertificateTemplateType{},
		"keyfactor_oauth_security_claim": dataSourceOAuthSecurityClaimType{},
		"keyfactor_oauth_security_role":  dataSourceOAuthSecurityRoleType{},
		"keyfactor_role":                 dataSourceSecurityRoleType{},
		"keyfactor_identity":             dataSourceSecurityIdentityType{},
	}, nil
}

// // Utility functions
func boolToPointer(b bool) *bool {
	return &b
}

func intToPointer(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}

func stringToPointer(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
