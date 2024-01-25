package keyfactor

import (
	"context"
	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"os"
	"strconv"
	"time"
)

var stderr = os.Stderr

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

func (p *provider) Configure(ctx context.Context, req tfsdk.ConfigureProviderRequest, resp *tfsdk.ConfigureProviderResponse) {
	// Retrieve provider data from configuration
	var config providerData

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// User must provide a user to the provider
	var username string
	if config.Username.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddWarning(
			"Invalid provider username.",
			"Cannot use unknown value as `username`",
		)
		return
	}
	if config.Username.Null {
		username = os.Getenv("KEYFACTOR_USERNAME")
		config.Username.Value = username
	} else {
		username = config.Username.Value
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
		domain = os.Getenv("KEYFACTOR_DOMAIN")
		config.Domain.Value = domain
	} else {
		domain = config.Domain.Value
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
		apiKey = os.Getenv("KEYFACTOR_APPKEY")
		config.ApiKey.Value = apiKey
	} else {
		apiKey = config.ApiKey.Value
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
		password = os.Getenv("KEYFACTOR_PASSWORD")
		config.Password.Value = password
	} else {
		password = config.Password.Value
	}

	if password == "" && apiKey == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Invlaid provider credentials. ",
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
		host = os.Getenv("KEYFACTOR_HOSTNAME")
		config.Hostname.Value = host
	} else {
		host = config.Hostname.Value
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
		timeout := os.Getenv("KEYFACTOR_TIMEOUT")
		if timeout == "" {
			config.RequestTimeout.Value = 30
		} else {
			//convert string to int
			timeoutInt, err := strconv.Atoi(timeout)
			if err != nil {
				resp.Diagnostics.AddError(
					"Invalid provider `timeout`.",
					"Provider `timeout` must be an integer.",
				)
				return
			}
			config.RequestTimeout.Value = int64(timeoutInt)
		}

	}

	// Create a new Keyfactor client and set it to the provider client
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
		c, err := api.NewKeyfactorClient(&clientAuth)

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
		p.configured = true
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
