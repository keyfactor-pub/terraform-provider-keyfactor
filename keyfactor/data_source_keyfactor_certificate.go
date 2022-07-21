package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceKeyfactorCertificate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceKeyfactorCertificateRead,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"csr": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Base-64 encoded certificate signing request (CSR)",
			},
			"key_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password to protect certificate and private key with",
			},
			"subject": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Certificate subject",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"subject_common_name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subject common name for new certificate",
						},
						"subject_locality": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subject locality for new certificate",
						},
						"subject_organization": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subject organization for new certificate",
						},
						"subject_state": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subject state for new certificate",
						},
						"subject_country": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subject country for new certificate",
						},
						"subject_organizational_unit": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subject organizational unit for new certificate",
						},
					},
				},
			},
			"certificate_authority": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of certificate authority to deploy certificate with Ex: Example Company CA 1",
			},
			"cert_template": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Short name of certificate template to be deployed",
			},
			"sans": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Certificate subject-alternative names",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"san_ip4": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "List of IPv4 addresses to use as subjects of the certificate",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"san_uri": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "List of IPv6 addresses to use as subjects of the certificate",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"san_dns": {
							Type:        schema.TypeList,
							Computed:    true,
							Description: "List of DNS names to use as subjects of the certificate",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"metadata": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Metadata key-value pairs to be attached to certificate",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"collection_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Collection identifier used to validate user permissions (if service account has global permissions, this is not needed)",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Serial number of newly enrolled certificate",
			},
			"issuer_dn": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Issuer distinguished name that signed the certificate",
			},
			"thumbprint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Thumbprint of newly enrolled certificate",
			},
			"keyfactor_id": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Keyfactor certificate ID",
			},
			"keyfactor_request_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Keyfactor request ID necessary for deploying certificate",
			},
			"certificate_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "PEM formatted certificate",
			},
			"certificate_chain": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "PEM formatted certificate chain",
			},
			"private_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "PEM formatted PKCS#1 private key imported if cert_template has KeyRetention set to a value other than None, and the certificate was not enrolled using a CSR.",
			},
		},
	}
}

func dataSourceKeyfactorCertificateRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	//certificateCN := d.Get("subject").(string)
	//fmt.Printf("[DEBUG] Subject: %s\n", certificateCN)

	certificateData := resourceCertificateRead(ctx, d, m)
	d.SetId(fmt.Sprintf("%v", d.Get("keyfactor_id").(int)))
	return certificateData

	// If we get here, the certificate name doesn't exist in Keyfactor.
	//return diag.Diagnostics{
	//	{
	//		Severity: diag.Error,
	//		Summary:  fmt.Sprintf("Keyfactor certificate %s was not found.", certificateCN),
	//		Detail:   "Please ensure that role_name contains a certificate that exists in Keyfactor.",
	//	},
	//}
}
