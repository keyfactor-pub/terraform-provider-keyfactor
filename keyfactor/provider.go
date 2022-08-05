package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"os"
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
				Description: "Hostname of Keyfactor instance. Ex: keyfactor.examplecompany.com",
			},

			"username": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Username of Keyfactor service account",
			},

			"password": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Password of Keyfactor service account",
			},

			"appkey": {
				Type:        types.StringType,
				Optional:    true,
				Sensitive:   true,
				Description: "Application key provisioned by Keyfactor instance",
			},

			"domain": {
				Type:        types.StringType,
				Optional:    true,
				Description: "Domain that Keyfactor instance is hosted on",
			},
		},
	}, nil
}

// Provider schema struct
type providerData struct {
	Username types.String `tfsdk:"username"`
	Hostname types.String `tfsdk:"hostname"`
	Password types.String `tfsdk:"password"`
	ApiKey   types.String `tfsdk:"appkey"`
	Domain   types.String `tfsdk:"domain"`
}

func (p *provider) Configure(ctx context.Context, req tfsdk.ConfigureProviderRequest, resp *tfsdk.ConfigureProviderResponse) {
	// Retrieve provider data from configuration
	var config providerData

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Environmentals: %v", os.Environ()))

	// User must provide a user to the provider
	var username string
	if config.Username.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddWarning(
			"Unable to create client",
			"Cannot use unknown value as username",
		)
		return
	}

	if config.Username.Null {
		username = os.Getenv("KEYFACTOR_USERNAME")
	} else {
		username = config.Username.Value
	}

	if username == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Unable to find username",
			"Username cannot be an empty string",
		)
		return
	}

	// User must provide a password to the provider
	var apiKey string
	if config.ApiKey.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddError(
			"Unable to create client",
			"Cannot use unknown value as password",
		)
		return
	}

	if config.ApiKey.Null {
		apiKey = os.Getenv("KEYFACTOR_APPKEY")
	} else {
		apiKey = config.Password.Value
	}

	// User must provide a password to the provider
	var password string
	if config.Password.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddError(
			"Unable to create client",
			"Cannot use unknown value as password",
		)
		return
	}

	if config.Password.Null {
		password = os.Getenv("KEYFACTOR_PASSWORD")
	} else {
		password = config.Password.Value
	}

	if password == "" && apiKey == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Unable to find password or API key",
			"password and API key cannot both be empty string",
		)
		return
	}

	// User must specify a host
	var host string
	if config.Hostname.Unknown {
		// Cannot connect to client with an unknown value
		resp.Diagnostics.AddError(
			"Unable to create client",
			"Cannot use unknown value as host",
		)
		return
	}

	if config.Hostname.Null {
		host = os.Getenv("KEYFACTOR_HOSTNAME")
	} else {
		host = config.Hostname.Value
	}

	if host == "" {
		// Error vs warning - empty value must stop execution
		resp.Diagnostics.AddError(
			"Unable to find host",
			"Host cannot be an empty string",
		)
		return
	}

	// Create a new HashiCups client and set it to the provider client
	var clientAuth api.AuthConfig
	clientAuth.Username = config.Username.Value
	clientAuth.Password = config.Password.Value
	//clientAuth.ApiKey = config.ApiKey.Value //TODO: Add API key support
	clientAuth.Domain = config.Domain.Value
	clientAuth.Hostname = config.Hostname.Value

	c, err := api.NewKeyfactorClient(&clientAuth)

	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to create client",
			"Unable to create Keyfactor GO client client:\n\n"+err.Error(),
		)
		return
	}

	p.client = c
	p.configured = true
}

// GetResources - Defines provider resources
func (p *provider) GetResources(_ context.Context) (map[string]tfsdk.ResourceType, diag.Diagnostics) {
	return map[string]tfsdk.ResourceType{
		"keyfactor_security_identity": resourceSecurityIdentityType{},
	}, nil
}

// GetDataSources - Defines provider data sources
func (p *provider) GetDataSources(_ context.Context) (map[string]tfsdk.DataSourceType, diag.Diagnostics) {
	return map[string]tfsdk.DataSourceType{}, nil
}

//// Nice-to-have functions
//
func interfaceArrayToStringTuple(m []interface{}) []api.StringTuple {
	// Unpack metadata expects []interface{} containing a list of lists of key-value pairs
	if len(m) > 0 {
		temp := make([]api.StringTuple, len(m)) // size of m is the number of metadata fields provided by .tf file
		for i, field := range m {
			temp[i].Elem1 = field.(map[string]interface{})["name"].(string)  // Unless changed in the future, this interface
			temp[i].Elem2 = field.(map[string]interface{})["value"].(string) // will always have 'name' and 'value'
		}
		return temp
	}
	return nil
}

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
