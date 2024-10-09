package keyfactor

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var stderr = os.Stderr
var LOG_INSECURE = false //todo: WARNING Do not set to true for a public release

func New() tfsdk.Provider {
	return &provider{}
}

type provider struct {
	configured bool
	client     *api.Client
}

// GetSchema
func (p *provider) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"hostname": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Hostname of Keyfactor Command instance. Ex: keyfactor.examplecompany.com. This can also be set via the `KEYFACTOR_HOSTNAME` environment variable.",
			},

			"username": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Username of Keyfactor Command service account. This can also be set via the `KEYFACTOR_USERNAME` environment variable.",
			},

			"password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Password of Keyfactor Command service account. This can also be set via the `KEYFACTOR_PASSWORD` environment variable.",
			},

			"appkey": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Application key provisioned by Keyfactor Command instance. This can also be set via the `KEYFACTOR_APPKEY` environment variable.",
			},

			"domain": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Domain that Keyfactor Command instance is hosted on. This can also be set via the `KEYFACTOR_DOMAIN` environment variable.",
			},
			"request_timeout": {
				Type:        types.Int64Type,
				Optional:    true,
				Description: "Global timeout for HTTP requests to Keyfactor Command instance. Default is 30 seconds.",
			},
		},
	}, nil
}

// Provider schema struct
type providerData struct {
	Username       types.String `tfsdk:"username"`
	Hostname       types.String `tfsdk:"hostname"`
	Password       types.String `tfsdk:"password"`
	ApiKey         types.String `tfsdk:"appkey"`
	Domain         types.String `tfsdk:"domain"`
	RequestTimeout types.Int64  `tfsdk:"request_timeout"`
}

func loggingInsecure() bool {
	if os.Getenv("KEYFACTOR_LOG_INSECURE") == "true" || os.Getenv("TF_LOG_INSECURE") == "true" {
		LOG_INSECURE = true
	} //TODO: WARNING: THIS IS NOT A GOOD IDEA and should not be included in a public release
	return LOG_INSECURE
}

func (p *provider) Configure(
	ctx context.Context,
	req tfsdk.ConfigureProviderRequest,
	resp *tfsdk.ConfigureProviderResponse,
) {
	// Retrieve provider data from configuration
	var config providerData
	loggingInsecure()
	tflog.Debug(ctx, "Configuring Keyfactor provider")
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, "Error configuring Keyfactor provider")
		return
	}

	ctx = tflog.SetField(ctx, "hostname", config.Hostname.Value)
	ctx = tflog.SetField(ctx, "username", config.Username.Value)
	ctx = tflog.SetField(ctx, "domain", config.Domain.Value)
	ctx = tflog.SetField(ctx, "appkey", config.ApiKey.Value)
	ctx = tflog.SetField(ctx, "password", config.Password.Value)
	if config.Password.Value != "" && !LOG_INSECURE {
		ctx = tflog.MaskLogStrings(ctx, config.Password.Value)
	}
	ctx = tflog.SetField(ctx, "request_timeout", config.RequestTimeout.Value)
	tflog.Debug(ctx, "Provider configuration complete")

	// User must provide a user to the provider
	var username string
	if config.Username.Unknown {
		// Cannot connect to client with an unknown value
		tflog.Error(ctx, "Provider username is UNKNOWN")
		resp.Diagnostics.AddWarning(
			"Invalid provider username.",
			"Cannot use unknown value as `username`",
		)
		return
	}
	if config.Username.Null {
		tflog.Debug(ctx, fmt.Sprintf("Provider username is NULL, attempting to source from '%s'", EnvCommandUsername))
		username = os.Getenv(EnvCommandUsername)
		config.Username.Value = username
		ctx = tflog.SetField(ctx, "username", username)
		tflog.Debug(ctx, fmt.Sprintf("Provider username sourced from environmental variable '%s'", EnvCommandUsername))
	} else {
		username = config.Username.Value
		ctx = tflog.SetField(ctx, "username", username)
		tflog.Debug(ctx, "Provider username sourced provider config 'username'")
	}
	if username == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Invalid provider username.",
			"`username` cannot be an empty string.",
		)
		return
	}
	// User must provide a user to the provider
	var domain string
	if config.Domain.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddWarning(
			"Invalid provider `domain`.",
			"Cannot use unknown value for `domain`.",
		)
		return
	}
	if config.Domain.Null {
		tflog.Debug(ctx, fmt.Sprintf("Provider 'domain' is NULL, attempting to source from '%s'", EnvCommandDomain))
		domain = os.Getenv(EnvCommandDomain)
		config.Domain.Value = domain
		ctx = tflog.SetField(ctx, "domain", domain)
		tflog.Debug(ctx, fmt.Sprintf("Provider 'domain' sourced from environmental variable '%s'", EnvCommandDomain))
	} else {
		domain = config.Domain.Value
		ctx = tflog.SetField(ctx, "domain", domain)
		tflog.Debug(ctx, "Provider 'domain' sourced provider config 'domain'")
	}
	if domain == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Invalid provider `domain`.",
			"`domain` cannot be an empty string.",
		)
		return
	}

	// User must provide a password to the provider
	var apiKey string
	if config.ApiKey.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddError(
			"Invalid provider API key.",
			"Cannot use unknown value as `appkey`.",
		)
		return
	}

	if config.ApiKey.Null {
		tflog.Debug(ctx, fmt.Sprintf("Provider 'appkey' is NULL, attempting to source from '%s'", EnvCommandAppKey))
		apiKey = os.Getenv(EnvCommandAppKey)
		config.ApiKey.Value = apiKey
		ctx = tflog.SetField(ctx, "appkey", apiKey)
		if apiKey != "" && !LOG_INSECURE {
			ctx = tflog.MaskLogStrings(ctx, apiKey)
		}
		tflog.Debug(ctx, fmt.Sprintf("Provider 'appkey' sourced from environmental variable '%s'", EnvCommandAppKey))
	} else {
		apiKey = config.ApiKey.Value
		ctx = tflog.SetField(ctx, "appkey", apiKey)
		tflog.Debug(ctx, "Provider 'appkey' sourced provider config 'appkey'")
	}

	// User must provide a password to the provider
	var password string
	if config.Password.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddError(
			"Invalid provider `password`.",
			"Cannot use unknown value as `password`",
		)
		return
	}

	if config.Password.Null {
		tflog.Debug(ctx, fmt.Sprintf("Provider 'password' is NULL, attempting to source from '%s'", EnvCommandPassword))
		password = os.Getenv(EnvCommandPassword)
		config.Password.Value = password
		ctx = tflog.SetField(ctx, "password", password)
		if password != "" && !LOG_INSECURE {
			ctx = tflog.MaskLogStrings(ctx, password)
		}
		tflog.Debug(
			ctx,
			fmt.Sprintf("Provider 'password' sourced from environmental variable '%s'", EnvCommandPassword),
		)
	} else {
		password = config.Password.Value
		ctx = tflog.SetField(ctx, "password", password)
		if password != "" && !LOG_INSECURE {
			ctx = tflog.MaskLogStrings(ctx, password)
		}
		tflog.Debug(ctx, "Provider 'password' sourced provider config 'password'")
	}

	if password == "" && apiKey == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Invalid provider credentials. ",
			"`password` and `appkey` cannot both be empty string.",
		)
		return
	}

	// User must specify a host
	var host string
	if config.Hostname.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddError(
			"Invalid provider `host`.",
			"Cannot use unknown value as `host`.",
		)
		return
	}

	if config.Hostname.Null {
		tflog.Debug(ctx, fmt.Sprintf("Provider 'hostname' is NULL, attempting to source from '%s'", EnvCommandHostname))
		host = os.Getenv(EnvCommandHostname)
		config.Hostname.Value = host
		ctx = tflog.SetField(ctx, "hostname", host)
		tflog.Debug(
			ctx,
			fmt.Sprintf("Provider 'hostname' sourced from environmental variable '%s'", EnvCommandHostname),
		)
	} else {
		host = config.Hostname.Value
		ctx = tflog.SetField(ctx, "hostname", host)
		tflog.Debug(ctx, "Provider 'hostname' sourced provider config 'hostname'")
	}

	if host == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Invalid provider `host`.",
			"Provider `host` cannot be an empty string.",
		)
		return
	}

	// Set default request timeout
	if config.RequestTimeout.Null {
		tflog.Debug(ctx, "Provider 'request_timeout' is NULL, attempting to source from 'KEYFACTOR_TIMEOUT'")
		timeout := os.Getenv(EnvCommandTimeout)
		if timeout == "" {
			tflog.Debug(
				ctx,
				fmt.Sprintf("Provider 'request_timeout' not set, using default value of %d", MAX_WAIT_SECONDS),
			)
			ctx = tflog.SetField(ctx, "request_timeout", MAX_WAIT_SECONDS)
			config.RequestTimeout.Value = MAX_WAIT_SECONDS
		} else {
			//convert string to int
			tflog.Debug(
				ctx,
				fmt.Sprintf("Provider 'request_timeout' sourced from environmental variable '%s'", EnvCommandTimeout),
			)
			timeoutInt, err := strconv.Atoi(timeout)
			if err != nil {
				resp.Diagnostics.AddError(
					"Invalid provider `timeout`.",
					"Provider `timeout` must be an integer.",
				)
				return
			}
			config.RequestTimeout.Value = int64(timeoutInt)
			ctx = tflog.SetField(ctx, "request_timeout", timeoutInt)
		}
	}

	// Create a new Keyfactor client and set it to the provider client
	tflog.Debug(ctx, "Creating Keyfactor Command API client")
	var clientAuth api.AuthConfig
	clientAuth.Username = config.Username.Value
	clientAuth.Password = config.Password.Value
	//clientAuth.ApiKey = config.ApiKey.Value //TODO: Add API key support
	clientAuth.Domain = config.Domain.Value
	clientAuth.Hostname = config.Hostname.Value
	clientAuth.Timeout = int(config.RequestTimeout.Value)

	connected := false
	connectionRetries := 0
	for !connected && connectionRetries < 5 {
		tflog.Debug(ctx, "Attempting to create client connection to Keyfactor Command")
		c, err := api.NewKeyfactorClient(&clientAuth, &ctx)

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
			tflog.Debug(ctx, "Failed to create client connection to Keyfactor Command. Retrying in 5 seconds.")
			time.Sleep(5 * time.Second)
			continue
		}
		connected = true
		p.client = c
		p.configured = true
		tflog.Debug(ctx, "Client connection to Keyfactor Command established successfully")
		return
	}
}

// GetResources - Defines provider resources
func (p *provider) GetResources(_ context.Context) (map[string]tfsdk.ResourceType, diag.Diagnostics) {
	return map[string]tfsdk.ResourceType{
		"keyfactor_identity":               resourceSecurityIdentityType{},
		"keyfactor_certificate":            resourceKeyfactorCertificateType{},
		"keyfactor_certificate_store":      resourceCertificateStoreType{},
		"keyfactor_certificate_deployment": resourceKeyfactorCertificateDeploymentType{},
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
