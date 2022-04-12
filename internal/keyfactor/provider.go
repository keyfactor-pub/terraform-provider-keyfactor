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
		},
		ResourcesMap: map[string]*schema.Resource{
			"keyfactor_certificate":       resourceCertificate(),
			"keyfactor_store":             resourceStore(),
			"keyfactor_security_identity": resourceSecurityIdentity(),
			"keyfactor_security_role":     resourceSecurityRole(),
			"keyfactor_attach_role":       resourceKeyfactorAttachRole(),
		},
		DataSourcesMap:       map[string]*schema.Resource{},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	var clientAuth keyfactor.AuthConfig
	if hostname := d.Get("hostname"); hostname.(string) != "" {
		clientAuth.Hostname = hostname.(string)
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Keyfactor Hostname required",
			Detail:   "Unable to authenticate user, export environment variable or configure hostname in schema.",
		})
	}
	if username := d.Get("kf_username"); username.(string) != "" {
		clientAuth.Username = username.(string)
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Keyfactor Username required",
			Detail:   "Unable to authenticate user, export environment variable or configure username in schema.",
		})
	}
	if password := d.Get("kf_password"); password.(string) != "" {
		clientAuth.Password = password.(string)
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Keyfactor Username required",
			Detail:   "Unable to authenticate user, export environment variable or configure username in schema.",
		})
	}
	if domain, ok := d.GetOk("domain"); ok {
		clientAuth.Domain = domain.(string)
	}

	clientAuth.Hostname = strings.TrimRight(clientAuth.Hostname, "/") // remove trailing slash, if it exists

	if len(diags) > 0 {
		return nil, diags
	}

	client, err := keyfactor.NewKeyfactorClient(&clientAuth)
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
