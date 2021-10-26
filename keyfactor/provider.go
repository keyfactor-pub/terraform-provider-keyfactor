package keyfactor

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"keyfactor-go-client/pkg/keyfactor"
)

// init provider block
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"hostname": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KEYFACTOR_HOSTNAME", nil),
				Description: "Hostname of Keyfactor instance. Ex: keyfactor.examplecompany.com",
			},

			"kf_username": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KEYFACTOR_USERNAME", nil),
				Description: "Username of Keyfactor service account",
			},

			"kf_password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("KEYFACTOR_PASSWORD", nil),
				Description: "Password of Keyfactor service account",
			},

			"kf_appkey": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("KEYFACTOR_APPKEY", nil),
				Description: "Application key provisioned by Keyfactor instance",
			},

			"domain": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("DOMAIN", nil),
				Description: "Domain that Keyfactor instance is hosted on",
			},

			"dev_mode": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KEYFACTOR_DEVMODE", nil),
				Description: "Development mode",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"keyfactor_certificate": resourceCertificate(),
			"keyfactor_store":       resourceStore(),
		},
		DataSourcesMap:       map[string]*schema.Resource{},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	var client keyfactor.APIClient
	hostname := d.Get("hostname").(string)
	username := d.Get("kf_username").(string)
	password := d.Get("kf_password").(string)
	domain := d.Get("domain").(string)

	hostname = strings.TrimRight(hostname, "/") // remove trailing slash, if it exists

	if (hostname != "") && (username != "") && (password != "") {
		client = keyfactor.APIClient{
			Hostname: hostname,
			Username: username,
			Password: password,
			Domain:   domain,
		}
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to connect to Keyfactor",
			Detail:   "Unable to authenticate user, check schema or environment variables",
		})
	}

	return &client, diags
}
