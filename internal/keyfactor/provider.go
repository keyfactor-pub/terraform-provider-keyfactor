package keyfactor

import (
	"context"
	"os"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider init provider block
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: func() (interface{}, error) {
					if v := os.Getenv("KEYFACTOR_HOSTNAME"); v != "" {
						return v, nil
					}
					return "", nil
				},
				Description: "Hostname of Keyfactor instance. Ex: keyfactor.examplecompany.com",
			},

			"kf_username": {
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: func() (interface{}, error) {
					if v := os.Getenv("KEYFACTOR_USERNAME"); v != "" {
						return v, nil
					}
					return "", nil
				},
				Description: "Username of Keyfactor service account",
			},

			"kf_password": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				DefaultFunc: func() (interface{}, error) {
					if v := os.Getenv("KEYFACTOR_PASSWORD"); v != "" {
						return v, nil
					}
					return "", nil
				},
				Description: "Password of Keyfactor service account",
			},

			"kf_appkey": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				DefaultFunc: func() (interface{}, error) {
					if v := os.Getenv("KEYFACTOR_APPKEY"); v != "" {
						return v, nil
					}
					return "", nil
				},
				Description: "Application key provisioned by Keyfactor instance",
			},

			"domain": {
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: func() (interface{}, error) {
					if v := os.Getenv("KEYFACTOR_DOMAIN"); v != "" {
						return v, nil
					}
					return "", nil
				},
				Description: "Domain that Keyfactor instance is hosted on",
			},

			"dev_mode": {
				Type:     schema.TypeBool,
				Optional: true,
				DefaultFunc: func() (interface{}, error) {
					if v := os.Getenv("KEYFACTOR_DEVMODE"); v != "" {
						return v, nil
					}
					return false, nil
				},
				Description: "Development mode",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"keyfactor_certificate":       resourceCertificate(),
			"keyfactor_store":             resourceStore(),
			"keyfactor_security_identity": resourceSecurityIdentity(),
			"keyfactor_security_role":     resourceSecurityRole(),
		},
		DataSourcesMap:       map[string]*schema.Resource{},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	var clientAuth *keyfactor.AuthConfig
	hostname := d.Get("hostname").(string)
	username := d.Get("kf_username").(string)
	password := d.Get("kf_password").(string)
	domain := d.Get("domain").(string)

	hostname = strings.TrimRight(hostname, "/") // remove trailing slash, if it exists

	if (hostname != "") && (username != "") && (password != "") {
		clientAuth = &keyfactor.AuthConfig{
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
		return nil, diags
	}

	client, err := keyfactor.NewKeyfactorClient(clientAuth)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	return client, diags
}

// Nice-to-have functions

func interfaceArrayToStringTuple(m []interface{}) []keyfactor.StringTuple {
	// Unpack metadata expects []interface{} containing a list of lists of key-value pairs
	if len(m) > 0 {
		temp := make([]keyfactor.StringTuple, len(m), len(m)) // size of m is the number of metadata fields provided by .tf file
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
