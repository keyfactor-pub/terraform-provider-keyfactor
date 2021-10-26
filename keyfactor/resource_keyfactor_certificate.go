package keyfactor

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"keyfactor-go-client/pkg/keyfactor"
	"strconv"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceCertificateCreate,
		ReadContext:   resourceCertificateRead,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,
		Schema: map[string]*schema.Schema{
			"certificate": &schema.Schema{
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"csr": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Base-64 encoded certificate signing request (CSR)",
						},
						"friendly_name": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Custom name of the certificate to be deployed",
						},
						"key_password": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							Description: "Password to protect certificate and private key with",
						},
						"populate_missing_values_from_ad": &schema.Schema{
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     false,
							Description: "Option to populate missing values from AD associated with instance",
						},
						"subject": &schema.Schema{
							Type:        schema.TypeList,
							MaxItems:    1,
							Required:    true,
							Description: "Certificate subject",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"subject_common_name": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Subject common name for new certificate",
									},
									"subject_locality": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Subject locality for new certificate",
									},
									"subject_organization": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Subject organization for new certificate",
									},
									"subject_state": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Subject state for new certificate",
									},
									"subject_country": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Subject country for new certificate",
									},
									"subject_organizational_unit": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Subject organizational unit for new certificate",
									},
								},
							},
						},
						"include_chain": &schema.Schema{
							Type:        schema.TypeBool,
							Optional:    true,
							Default:     true,
							Description: "Include entire certificate chain?",
						},
						"renewal_certificate_id": &schema.Schema{
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Certificate ID of certificate to renew",
						},
						"certificate_authority": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Name of certificate authority to deploy certificate with Ex: Example Company CA 1",
						},
						"cert_template": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Short name of certificate template to be deployed",
						},
						"sans": &schema.Schema{
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Description: "Certificate subject-alternative names",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"san_ip4": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of IPv4 addresses to use as subjects of the certificate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"san_ip6": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of IPv6 addresses to use as subjects of the certificate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"san_uri": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of IPv6 addresses to use as subjects of the certificate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"san_dns": &schema.Schema{
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of DNS names to use as subjects of the certificate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"metadata": &schema.Schema{
							Type:        schema.TypeList,
							Optional:    true,
							Description: "",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"certificate_format": &schema.Schema{
							Type:        schema.TypeString,
							Optional:    true,
							Default:     "PEM",
							Description: "Format of certificate requested. (PEM, JKS, STORE)",
						},
						"collection_id": &schema.Schema{
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Collection identifier used to validate user permissions (if service account has global permissions, this is not needed)",
						},
						"certificate": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"serial_number": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"issuer_dn": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"thumbprint": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"keyfactor_id": &schema.Schema{
							Type:     schema.TypeInt,
							Computed: true,
						},
						"keyfactor_request_id": &schema.Schema{
							Type:     schema.TypeInt,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClientData := m.(*keyfactor.APIClient)

	certificates := d.Get("certificate").([]interface{})

	for _, certificate := range certificates {
		i := certificate.(map[string]interface{})
		subject := i["subject"].([]interface{})[0].(map[string]interface{}) // Extract subject data from schema
		sans := i["sans"].([]interface{})[0].(map[string]interface{})       // Extract SANs from schema

		if i["csr"] != "" {
			CSRArgs := &keyfactor.EnrollCSRFctArgs{
				CSR:                  i["csr"].(string),
				CertificateAuthority: i["certificate_authority"].(string),
				Template:             i["cert_template"].(string),
				IncludeChain:         i["include_chain"].(bool),
				CertFormat:           i["certificate_format"].(string),
				CertificateSANs:      getSans(sans),
			}
			response, err := keyfactor.EnrollCSR(CSRArgs, kfClientData)
			if err != nil {
				return diag.FromErr(err)
			}

			// Set computed schema
			err = d.Set("serial_number", response.CertificateInformation.SerialNumber)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("issuer_dn", response.CertificateInformation.IssuerDN)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("thumbprint", response.CertificateInformation.Thumbprint)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("keyfactor_id", response.CertificateInformation.KeyfactorID)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("keyfactor_request_id", response.CertificateInformation.KeyfactorRequestID)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("certificate", response.Certificates)
			if err != nil {
				return diag.FromErr(err)
			}

			// Set resource ID to tell Terraform that operation was successful
			d.SetId(strconv.Itoa(response.CertificateInformation.KeyfactorID))
		} else {

			PFXArgs := &keyfactor.EnrollPFXFctArgs{
				CustomFriendlyName:          i["friendly_name"].(string),
				KeyPassword:                 i["key_password"].(string),
				PopulateMissingValuesFromAD: i["populate_missing_values_from_ad"].(bool),
				CertificateAuthority:        i["certificate_authority"].(string),
				Template:                    i["cert_template"].(string),
				IncludeChain:                i["include_chain"].(bool),
				RenewalCertificateId:        i["renewal_certificate_id"].(int),
				CertFormat:                  i["certificate_format"].(string),
				CertificateSANs:             getSans(sans), // if no SANs are specified, this field is nil
				CertificateSubject: keyfactor.CertificateSubject{
					SubjectCommonName:         subject["subject_common_name"].(string),
					SubjectLocality:           subject["subject_locality"].(string),
					SubjectOrganization:       subject["subject_organization"].(string),
					SubjectCountry:            subject["subject_country"].(string),
					SubjectOrganizationalUnit: subject["subject_organizational_unit"].(string),
					SubjectState:              subject["subject_state"].(string),
				},
			}
			// Error checking for invalid fields inside PFX enrollment function
			response, err := keyfactor.EnrollPFX(PFXArgs, kfClientData) // If no CSR is present, enroll a PFX certificate
			if err != nil {
				return diag.FromErr(err)
			}

			// Set computed schema
			err = d.Set("serial_number", response.CertificateInformation.SerialNumber)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("issuer_dn", response.CertificateInformation.IssuerDN)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("thumbprint", response.CertificateInformation.Thumbprint)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("keyfactor_id", response.CertificateInformation.KeyfactorID)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("keyfactor_request_id", response.CertificateInformation.KeyfactorRequestID)
			if err != nil {
				return diag.FromErr(err)
			}
			err = d.Set("certificate", response.Certificate)
			if err != nil {
				return diag.FromErr(err)
			}

			// Set resource ID to tell Terraform that operation was successful
			d.SetId(strconv.Itoa(response.CertificateInformation.KeyfactorID))
		}
	}
	return diags
}

func getSans(s interface{}) *keyfactor.SANs {
	sans := &keyfactor.SANs{}

	// Retrieve individual SANs for each category and append to new SANs data structure
	for _, san := range s.(map[string]interface{})["san_ip4"].([]interface{}) {
		sans.IP4 = append(sans.IP4, san.(string))
	}
	for _, san := range s.(map[string]interface{})["san_ip6"].([]interface{}) {
		sans.IP6 = append(sans.IP6, san.(string))
	}
	for _, san := range s.(map[string]interface{})["san_uri"].([]interface{}) {
		sans.URI = append(sans.URI, san.(string))
	}
	for _, san := range s.(map[string]interface{})["san_dns"].([]interface{}) {
		sans.DNS = append(sans.DNS, san.(string))
	}

	return sans
}

func parseMetadata(d *schema.ResourceData) *keyfactor.Metadata {
	// Metadata specified in .tf files using TypeMap
	// Default state representation of maps include the count of items inside a map (%)
	// To change the expected behavior according to a specific Keyfactor instance, adjust expected values.

	return nil
}

func resourceCertificateRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func resourceCertificateUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func resourceCertificateDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.
	// Typically, this is not common in production

	revokeArgs := &keyfactor.RevokeCertArgs{
		CertificateIds: []int{d.Get("keyfactor_id").(int)}, // Certificate ID expects array of integers
		Reason:         5,                                  // reason = 5 means Cessation of Operation
		Comment:        "Terraform resource delete called on provider with associated cert ID",
		CollectionId:   d.Get("collection_id").(int),
	}

	kfClientData := m.(*keyfactor.APIClient)

	err := keyfactor.RevokeCert(revokeArgs, kfClientData)
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}
