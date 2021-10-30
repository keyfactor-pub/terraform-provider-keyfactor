package keyfactor

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"keyfactor-go-client/pkg/keyfactor"
	"log"
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
						"revoke_on_destroy": &schema.Schema{
							Type:        schema.TypeBool,
							Optional:    true,
							Computed:    true,
							Description: "Set to true to revoke certificate upon calling terraform destroy",
						},
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
							Description: "Metadata key-value pairs to be attached to certificate",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Name of metadata field as seen in Keyfactor",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"value": &schema.Schema{
										Type:        schema.TypeString,
										Optional:    true,
										Description: "Metadata value",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
								},
							},
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
						"certificates": &schema.Schema{
							Type:     schema.TypeList,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
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
		metadata := i["metadata"].([]interface{})

		format := i["certificate_format"].(string)
		if format == "PEM" || format == "DER" || format == "P7B" {
			format = "STORE" // Enroll endpoint expects STORE, PFX, or Zip
		}

		if i["csr"] != "" {
			CSRArgs := &keyfactor.EnrollCSRFctArgs{
				CSR:                  i["csr"].(string),
				CertificateAuthority: i["certificate_authority"].(string),
				Template:             i["cert_template"].(string),
				IncludeChain:         i["include_chain"].(bool),
				CertFormat:           i["certificate_format"].(string),
				CertificateSANs:      getSans(sans),
				CertificateMetadata:  unpackMetadata(metadata),
			}
			response, err := keyfactor.EnrollCSR(CSRArgs, kfClientData)
			if err != nil {
				return diag.FromErr(err)
			}

			// Attempt to retrieve the correct certificate format
			format = i["certificate_format"].(string)
			if format == "PEM" || format == "DER" || format == "P7B" {
				// Download certificate updates the certificates field of the enroll response
				// with the correct certificate format
				if err, response.Certificates = downloadCertificate(response.CertificateInformation.KeyfactorID, kfClientData, format); err != nil {
					return diag.FromErr(err)
				}
			}

			// Set computed schema
			data := flattenEnrollResponse(response)
			if err := d.Set("certificate", data); err != nil {
				return diag.FromErr(err)
			}

			// Set resource ID to tell Terraform that operation was successful*
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
				CertFormat:                  format,
				CertificateSANs:             getSans(sans), // if no SANs are specified, this field is nil
				CertificateMetadata:         unpackMetadata(metadata),
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

			// Attempt to retrieve the correct certificate format
			format = i["certificate_format"].(string)
			if format == "PEM" || format == "DER" || format == "P7B" {
				// Download certificate updates the certificates field of the enroll response
				// with the correct certificate format
				if err, response.Certificates = downloadCertificate(response.CertificateInformation.KeyfactorID, kfClientData, format); err != nil {
					return diag.FromErr(err)
				}
			}

			// Set computed schema
			data := flattenEnrollResponse(response)
			if err := d.Set("certificate", data); err != nil {
				return diag.FromErr(err)
			}

			// Set resource ID to tell Terraform that operation was successful
			d.SetId(strconv.Itoa(response.CertificateInformation.KeyfactorID))
		}
	}
	return diags
}

func flattenEnrollResponse(response *keyfactor.EnrollResponse) []interface{} {
	if response != nil {
		temp := make([]interface{}, 1, 1)
		data := make(map[string]interface{})

		// Build an interface array and populate with certificates inside EnrollResponse
		certs := make([]interface{}, len(response.Certificates), len(response.Certificates))
		for i, cert := range response.Certificates {
			certs[i] = cert
		}
		// Assign response data to associated schema
		data["certificates"] = certs
		data["serial_number"] = response.CertificateInformation.SerialNumber
		data["issuer_dn"] = response.CertificateInformation.IssuerDN
		data["thumbprint"] = response.CertificateInformation.Thumbprint
		data["keyfactor_id"] = response.CertificateInformation.KeyfactorID
		data["keyfactor_request_id"] = response.CertificateInformation.KeyfactorRequestID
		temp[0] = data // For now, only one certificate can be enrolled per resource instance
		return temp
	}
	return make([]interface{}, 0)
}

func downloadCertificate(id int, api *keyfactor.APIClient, format string) (error, []string) {
	downloadArgs := &keyfactor.DownloadCertArgs{
		CertID:       id,
		IncludeChain: true,
		CertFormat:   format,
	}

	resp, err := keyfactor.DownloadCertificate(downloadArgs, api)
	if err != nil {
		return err, nil
	}
	temp := []string{resp.Content}
	return nil, temp
}

func getSans(s interface{}) *keyfactor.SANs {
	sans := &keyfactor.SANs{}

	// Retrieve individual SANs for each category and append to new SANs data structure
	// Maybe separate these for loops to their own function?
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

func unpackMetadata(m []interface{}) []keyfactor.StringTuple {
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

func resourceCertificateRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func resourceCertificateUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func updateMetadata(id int, api *keyfactor.APIClient, metadata []keyfactor.StringTuple) error {
	args := &keyfactor.UpdateMetadataArgs{
		CertID:              id,
		CertificateMetadata: metadata,
	}

	err := keyfactor.UpdateMetadata(args, api)
	if err != nil {
		return err
	}

	return nil
}

func resourceCertificateDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	log.Println("[INFO] Deleting certificate resource")

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.
	// Typically, this is not common in production
	kfClientData := m.(*keyfactor.APIClient)

	certificates := d.Get("certificate").([]interface{})

	for _, certificate := range certificates {
		i := certificate.(map[string]interface{})
		// Only revoke if revoke_on_destroy is true
		if i["revoke_on_destroy"].(bool) == true {
			log.Println("[INFO] Revoking certificate in Keyfactor")
			revokeArgs := &keyfactor.RevokeCertArgs{
				CertificateIds: []int{i["keyfactor_id"].(int)}, // Certificate ID expects array of integers
				Reason:         5,                              // reason = 5 means Cessation of Operation
				Comment:        "Terraform destroy called on provider with associated cert ID",
				CollectionId:   i["collection_id"].(int),
			}

			err := keyfactor.RevokeCert(revokeArgs, kfClientData)
			if err != nil {
				return diag.FromErr(err)
			}
		}

	}
	return diags
}
