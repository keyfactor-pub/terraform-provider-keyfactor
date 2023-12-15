// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"fmt"
	kfc "github.com/Keyfactor/keyfactor-go-client-sdk/v2/api/command"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"net/http"
	"os"
	"strings"
)

// Ensure Provider satisfies various provider interfaces.
var _ provider.Provider = &Provider{}

// Provider defines the provider implementation.
type Provider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// ProviderModel describes the provider data model.
type ProviderModel struct {
	Username     types.String `tfsdk:"username"`
	Hostname     types.String `tfsdk:"hostname"`
	Password     types.String `tfsdk:"password"`
	Domain       types.String `tfsdk:"domain"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	AuthConfig   types.String `tfsdk:"auth_config"`
}

func (p *Provider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "keyfactor_command"
	resp.Version = p.version
}

func (p *Provider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"hostname": schema.StringAttribute{
				CustomType:          nil,
				Required:            false,
				Optional:            true,
				Sensitive:           true,
				Description:         "Keyfactor Command hostname including any non-standard port.",
				MarkdownDescription: "Keyfactor Command hostname including any non-standard port.",
				DeprecationMessage:  "",
				Validators:          nil,
			},
			"username": schema.StringAttribute{
				CustomType:          nil,
				Required:            false,
				Optional:            true,
				Sensitive:           true,
				Description:         "The username used to authenticate to Keyfactor Command, if using basic auth. Must be used in conjunction with password.",
				MarkdownDescription: "The username used to authenticate to Keyfactor Command, if using basic auth. Must be used in conjunction with password.",
				DeprecationMessage:  "",
				Validators:          nil,
			},
			"password": schema.StringAttribute{
				CustomType:          nil,
				Required:            false,
				Optional:            true,
				Sensitive:           true,
				Description:         "The password used to authenticate to Keyfactor Command, if using basic auth. Must be used in conjunction with username.",
				MarkdownDescription: "The password used to authenticate to Keyfactor Command, if using basic auth. Must be used in conjunction with username.",
				DeprecationMessage:  "",
				Validators:          nil,
			},
			"domain": schema.StringAttribute{
				CustomType:          nil,
				Required:            false,
				Optional:            true,
				Sensitive:           true,
				Description:         "The active directory domain of the username used to authenticate to Keyfactor Command, if using basic auth. This can be provided in the username field as well by using one of the following patterns: '<domain>\\username' or 'username@domain'.",
				MarkdownDescription: "The active directory domain of the username used to authenticate to Keyfactor Command, if using basic auth. This can be provided in the username field as well by using one of the following patterns: '<domain>\\username' or 'username@domain'.",
				DeprecationMessage:  "",
				Validators:          nil,
			},
			"client_id": schema.StringAttribute{
				CustomType:          nil,
				Required:            false,
				Optional:            true,
				Sensitive:           true,
				Description:         "The client ID to authenticate to Keyfactor Command, if using oauth. Must be used in conjunction with client_secret.",
				MarkdownDescription: "The client ID to authenticate to Keyfactor Command, if using oauth. Must be used in conjunction with client_secret.",
				DeprecationMessage:  "",
				Validators:          nil,
			},
			"client_secret": schema.StringAttribute{
				CustomType:          nil,
				Required:            false,
				Optional:            true,
				Sensitive:           true,
				Description:         "The client secret to authenticate to Keyfactor Command, if using oauth. Must be used in conjunction with client_id.",
				MarkdownDescription: "The client secret to authenticate to Keyfactor Command, if using oauth. Must be used in conjunction with client_id.",
				DeprecationMessage:  "",
				Validators:          nil,
			},
			"auth_config": schema.StringAttribute{
				CustomType:          nil,
				Required:            false,
				Optional:            true,
				Sensitive:           true,
				Description:         "The path to the auth config file to use for authentication to Keyfactor Command. This can be used in place of the username, password, domain, client_id, and client_secret fields.",
				MarkdownDescription: "The path to the auth config file to use for authentication to Keyfactor Command. This can be used in place of the username, password, domain, client_id, and client_secret fields.",
				DeprecationMessage:  "",
				Validators:          nil,
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data ProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	username, _ := p.resolveUsername(data)
	tflog.SetField(ctx, "username", username)
	tflog.Debug(ctx, fmt.Sprintf("username: %s", username))

	password, _ := p.resolvePassword(data)
	if password != "" {
		tflog.MaskAllFieldValuesStrings(ctx, password)
	}
	tflog.SetField(ctx, "password", password)

	domain, _ := p.resolveDomain(data)
	tflog.SetField(ctx, "domain", domain)

	clientID, _ := p.resolveClientID(data)
	tflog.SetField(ctx, "client_id", clientID)

	clientSecret, _ := p.resolveClientSecret(data)
	if clientSecret != "" {
		tflog.MaskAllFieldValuesStrings(ctx, clientSecret)
	}
	tflog.SetField(ctx, "client_secret", clientSecret)

	host, _ := p.resolveHost(data)
	tflog.SetField(ctx, "host", host)

	tflog.Info(ctx, "Configuring Keyfactor Command provider")

	sdkClientConfig := make(map[string]string)
	sdkClientConfig["host"] = host
	sdkClientConfig["username"] = username
	sdkClientConfig["password"] = password
	sdkClientConfig["domain"] = domain

	configErr := p.validateConfig(&sdkClientConfig)
	if configErr != nil {
		resp.Diagnostics.AddError(
			"Command Configuration Error",
			fmt.Sprintf("Invalid configuration: %s", configErr.Error()),
		)
		return
	}

	configuration, cfgErr := kfc.NewConfiguration(sdkClientConfig)
	if cfgErr != nil {
		resp.Diagnostics.AddError(
			"Command Configuration Error",
			fmt.Sprintf("Unable to create Keyfactor Command configuration: %s", cfgErr.Error()),
		)
		return
	}
	c := kfc.NewAPIClient(configuration)

	maxRetries := 3
	for i := 0; i <= maxRetries; i++ {
		o, r, err := c.StatusApi.StatusGetEndpoints(nil).Execute()
		if err != nil {
			if i < maxRetries {
				tflog.Warn(ctx, fmt.Sprintf("Unable to authenticate to Keyfactor Command: %s", err.Error()))
				continue
			}
			resp.Diagnostics.AddError(
				"Command Authentication Error",
				fmt.Sprintf("Unable to authenticate to Keyfactor Command: %s", err.Error()),
			)
			return
		}
		if r.StatusCode != http.StatusOK {
			if i < maxRetries && (http.StatusRequestTimeout == r.StatusCode || http.StatusServiceUnavailable == r.StatusCode || http.StatusGatewayTimeout == r.StatusCode) {
				tflog.Warn(ctx, fmt.Sprintf("Unable to authenticate to Keyfactor Command: %s", o))
				continue
			}
			resp.Diagnostics.AddError(
				"Command Authentication Error",
				fmt.Sprintf("Unable to authenticate to Keyfactor Command: %s", o),
			)
			return
		} else {
			tflog.Info(ctx, fmt.Sprintf("Successfully authenticated to Keyfactor Command: %s", o))
			resp.DataSourceData = c
			resp.ResourceData = c
			return
		}
	}
}

func (p *Provider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *Provider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCertificateDataSource,
		NewAgentDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{
			version: version,
		}
	}
}

func (p *Provider) resolveUsername(data ProviderModel) (string, error) {
	var username string
	if data.Username.IsNull() || data.Username.IsUnknown() {
		username = os.Getenv("KEYFACTOR_CMD_USERNAME")
		if username == "" {
			username = os.Getenv("KEYFACTOR_USERNAME")
		}
	} else {
		username = data.Username.String()
	}
	return username, nil
}

func (p *Provider) resolvePassword(data ProviderModel) (string, error) {
	var password string
	if data.Password.IsNull() || data.Password.IsUnknown() {
		password = os.Getenv("KEYFACTOR_CMD_PASSWORD")
		if password == "" {
			password = os.Getenv("KEYFACTOR_PASSWORD")
		}
		if password == "" {
			password = os.Getenv("KEYFACTOR_CMD_CLIENT_SECRET")
			if password == "" {
				password = os.Getenv("KEYFACTOR_CLIENT_SECRET")
			}
		}
	} else {
		password = data.Password.String()
	}
	return password, nil
}

func (p *Provider) resolveDomain(data ProviderModel) (string, error) {
	var domain string
	if data.Domain.IsNull() || data.Domain.IsUnknown() {
		domain = os.Getenv("KEYFACTOR_CMD_DOMAIN")
		if domain == "" {
			domain = os.Getenv("KEYFACTOR_DOMAIN")
		}
	} else {
		domain = data.Domain.String()
	}
	if domain == "" {
		//try and parse from username
		username, _ := p.resolveUsername(data)
		if username != "" {
			if strings.Contains(username, "\\") {
				domain = strings.Split(username, "\\")[0]
			} else if strings.Contains(username, "@") {
				domain = strings.Split(username, "@")[1]
			}
		}
	}
	return domain, nil
}

func (p *Provider) resolveClientID(data ProviderModel) (string, error) {
	var clientID string
	if (data.ClientID.IsNull()) || (data.ClientID.IsUnknown()) {
		clientID = os.Getenv("KEYFACTOR_CMD_CLIENT_ID")
		if clientID == "" {
			clientID = os.Getenv("KEYFACTOR_CLIENT_ID")
		}
	} else {
		clientID = data.ClientID.String()
	}
	return clientID, nil
}

func (p *Provider) resolveClientSecret(data ProviderModel) (string, error) {
	var clientSecret string
	if data.Password.IsNull() || data.Password.IsUnknown() {
		clientSecret = os.Getenv("KEYFACTOR_CMD_CLIENT_SECRET")
		if clientSecret == "" {
			clientSecret = os.Getenv("KEYFACTOR_CLIENT_SECRET")
		}
	} else {
		clientSecret = data.ClientSecret.String()
	}
	return clientSecret, nil
}

func (p *Provider) resolveHost(data ProviderModel) (string, error) {
	var hostname string
	if data.Password.IsNull() || data.Password.IsUnknown() {
		hostname = os.Getenv("KEYFACTOR_CMD_HOSTNAME")
		if hostname == "" {
			hostname = os.Getenv("KEYFACTOR_HOSTNAME")
		}
	} else {
		hostname = data.Hostname.String()
	}
	return hostname, nil
}

// validateConfig validates the provider configuration.
// This returns an error if the following conditions are not met:
// - host not provided
// - username and client_id not provided
// - username and client_id both provided
// - password not provided when username provided
// - domain not provided when username provided
// - client_secret not provided when client_id provided
func (p *Provider) validateConfig(config *map[string]string) error {
	var errs []error
	if (*config)["host"] == "" {
		errs = append(errs, fmt.Errorf("host not provided"))
	}
	if ((*config)["username"] == "" && (*config)["client_id"] == "") || ((*config)["username"] != "" && (*config)["client_id"] != "") {
		errs = append(errs, fmt.Errorf("username and client_id not provided, or both provided"))
	}
	if (*config)["username"] != "" {
		if (*config)["password"] == "" {
			errs = append(errs, fmt.Errorf("password not provided when username provided"))
		}
		if (*config)["domain"] == "" {
			errs = append(errs, fmt.Errorf("domain not provided when username provided"))
		}
	}
	if (*config)["client_id"] != "" {
		if (*config)["client_secret"] == "" {
			errs = append(errs, fmt.Errorf("client_secret not provided when client_id provided"))
		}
	}
	if len(errs) > 0 {
		// combine errors into a single error
		var errStr string
		for _, err := range errs {
			errStr = fmt.Sprintf("%s%s\n", errStr, err.Error())
		}
		return fmt.Errorf(errStr)
	}
	return nil
}
