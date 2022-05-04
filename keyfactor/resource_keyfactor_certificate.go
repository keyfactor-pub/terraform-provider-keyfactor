package keyfactor

import (
	"context"
	"errors"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"strconv"
	"strings"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceCertificateCreate,
		ReadContext:   resourceCertificateRead,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,
		Schema: map[string]*schema.Schema{
			"csr": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base-64 encoded certificate signing request (CSR)",
			},
			"key_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password to protect certificate and private key with",
			},
			"subject": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Optional:    true,
				Description: "Certificate subject",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"subject_common_name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Subject common name for new certificate",
						},
						"subject_locality": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Subject locality for new certificate",
						},
						"subject_organization": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Subject organization for new certificate",
						},
						"subject_state": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Subject state for new certificate",
						},
						"subject_country": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Subject country for new certificate",
						},
						"subject_organizational_unit": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Subject organizational unit for new certificate",
						},
					},
				},
			},
			"certificate_authority": {
				Type:     schema.TypeString,
				Required: true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if strings.ToLower(old) == strings.ToLower(new) {
						return true
					}
					return false
				},
				Description: "Name of certificate authority to deploy certificate with Ex: Example Company CA 1",
			},
			"cert_template": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Short name of certificate template to be deployed",
			},
			"sans": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Optional:    true,
				Description: "Certificate subject-alternative names",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"san_ip4": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "List of IPv4 addresses to use as subjects of the certificate",
							DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
								// For some reason Terraform detects this particular function as having drift; this function
								// gives us a definitive answer.
								return !d.HasChange(k)
							},
							Elem: &schema.Schema{Type: schema.TypeString},
						},
						"san_uri": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "List of IPv6 addresses to use as subjects of the certificate",
							DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
								// For some reason Terraform detects this particular function as having drift; this function
								// gives us a definitive answer.
								return !d.HasChange(k)
							},
							Elem: &schema.Schema{Type: schema.TypeString},
						},
						"san_dns": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "List of DNS names to use as subjects of the certificate",
							DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
								// For some reason Terraform detects this particular function as having drift; this function
								// gives us a definitive answer.
								return !d.HasChange(k)
							},
							Elem: &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"metadata": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Metadata key-value pairs to be attached to certificate",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Name of metadata field as seen in Keyfactor",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"value": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Metadata value",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"collection_id": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Collection identifier used to validate user permissions (if service account has global permissions, this is not needed)",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Serial number of newly enrolled certificate",
			},
			"issuer_dn": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Issuer distinguished name that signed the certificate",
			},
			"thumbprint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Thumbprint of newly enrolled certificate",
			},
			"keyfactor_id": {
				Type:        schema.TypeInt,
				Computed:    true,
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
		},
	}
}

func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClient := m.(*keyfactor.Client)

	sans := d.Get("sans").([]interface{}) // Extract SANs from schema
	metadata := d.Get("metadata").([]interface{})
	csr := d.Get("csr").(string)
	if csr != "" {
		CSRArgs := &keyfactor.EnrollCSRFctArgs{
			CSR:                  csr,
			CertificateAuthority: d.Get("certificate_authority").(string),
			Template:             d.Get("cert_template").(string),
			IncludeChain:         true,
			CertFormat:           "PEM", // Retrieve certificate in READ
			CertificateSANs:      getSans(sans),
			CertificateMetadata:  interfaceArrayToStringTuple(metadata),
		}
		enrollResponse, err := kfClient.EnrollCSR(CSRArgs)
		if err != nil {
			resourceCertificateRead(ctx, d, m)
			return diag.FromErr(err)
		}

		// Set resource ID to tell Terraform that operation was successful
		d.SetId(strconv.Itoa(enrollResponse.CertificateInformation.KeyfactorID))

		resourceCertificateRead(ctx, d, m) // populate terraform state to current state after creation
	} else {
		subject := d.Get("subject").([]interface{})[0].(map[string]interface{}) // Extract subject data from schema
		PFXArgs := &keyfactor.EnrollPFXFctArgs{
			CustomFriendlyName:          "Terraform",
			KeyPassword:                 d.Get("key_password").(string),
			PopulateMissingValuesFromAD: false,
			CertificateAuthority:        d.Get("certificate_authority").(string),
			Template:                    d.Get("cert_template").(string),
			IncludeChain:                true,
			CertFormat:                  "STORE",       // Get certificate from data source
			CertificateSANs:             getSans(sans), // if no SANs are specified, this field is nil
			CertificateMetadata:         interfaceArrayToStringTuple(metadata),
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
		enrollResponse, err := kfClient.EnrollPFX(PFXArgs) // If no CSR is present, enroll a PFX certificate
		if err != nil {
			resourceCertificateRead(ctx, d, m)
			return diag.FromErr(err)
		}

		// Set resource ID to tell Terraform that operation was successful
		d.SetId(strconv.Itoa(enrollResponse.CertificateInformation.KeyfactorID))

		return resourceCertificateRead(ctx, d, m) // populate terraform state to current state after creation
	}
	return diags
}

func getSans(s []interface{}) *keyfactor.SANs {
	sans := &keyfactor.SANs{}

	if len(s) > 0 {
		temp := s[0].(map[string]interface{})
		// Retrieve individual SANs for each category and append to new SANs data structure
		// Maybe separate these for loops to their own function?
		for _, san := range temp["san_ip4"].([]interface{}) {
			sans.IP4 = append(sans.IP4, san.(string))
		}
		for _, san := range temp["san_uri"].([]interface{}) {
			sans.URI = append(sans.URI, san.(string))
		}
		for _, san := range temp["san_dns"].([]interface{}) {
			sans.DNS = append(sans.DNS, san.(string))
		}
		return sans
	}

	return nil
}

func resourceCertificateRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	kfClient := m.(*keyfactor.Client)

	var diags diag.Diagnostics

	Id := d.Id()
	CertificateId, err := strconv.Atoi(Id)
	if err != nil {
		return diag.FromErr(err)
	}

	// Get certificate context
	args := &keyfactor.GetCertificateContextArgs{
		IncludeMetadata:  boolToPointer(true),
		IncludeLocations: boolToPointer(true),
		CollectionId:     nil,
		Id:               CertificateId,
	}
	certificateData, err := kfClient.GetCertificateContext(args)
	if err != nil {
		return diag.FromErr(err)
	}

	// Get the password out of current schema
	password := d.Get("key_password").(string)
	metadata := d.Get("metadata").([]interface{})
	csr := d.Get("csr").(string)

	// Download and assign certificates to proper location
	err, pem := downloadCertificate(certificateData.Id, kfClient, "PEM")
	if err != nil {
		return diag.FromErr(err)
	}

	newSchema, err := flattenCertificateItems(certificateData, kfClient, pem, password, metadata, csr) // Set schema
	if err != nil {
		return diag.FromErr(err)
	}
	for key, value := range newSchema {
		err = d.Set(key, value)
		if err != nil {
			diags = append(diags, diag.FromErr(err)[0])
		}
	}

	return diags
}

func flattenCertificateItems(certificateContext *keyfactor.GetCertificateResponse, kfClient *keyfactor.Client, pem string, password string, oldMetadata []interface{}, csr string) (map[string]interface{}, error) {
	if certificateContext != nil {
		data := make(map[string]interface{})

		// Assign response data to associated schema
		data["serial_number"] = certificateContext.SerialNumber
		data["issuer_dn"] = certificateContext.IssuerDN
		data["thumbprint"] = certificateContext.Thumbprint
		data["keyfactor_id"] = certificateContext.Id
		data["keyfactor_request_id"] = certificateContext.CertRequestId

		// Assign non-computed schema
		templates, err := kfClient.GetTemplate(certificateContext.TemplateId)
		if err != nil {
			return make(map[string]interface{}), err
		}
		data["cert_template"] = templates.CommonName
		data["certificate_authority"] = certificateContext.CertificateAuthorityName

		// Assign schema that require flattening
		data["sans"] = flattenSANs(certificateContext.SubjectAltNameElements)
		data["metadata"] = flattenMetadata(certificateContext.Metadata, oldMetadata)
		// Subject should only be used if enroll PFX was used.
		if csr == "" {
			data["subject"] = flattenSubject(certificateContext.IssuedDN)
		}

		// Schema set by passed in values
		data["certificate_pem"] = pem
		if password != "" {
			data["key_password"] = password
		}
		if csr != "" {
			data["csr"] = csr
		}

		return data, nil
	}
	return make(map[string]interface{}), errors.New("failed to flatten certificate context schema; context struct nil")
}

func flattenSubject(subject string) []interface{} {
	if subject != "" {
		temp := make([]interface{}, 1, 1)            // Outer subject interface is a 1 wide array
		data := make(map[string]interface{})         // Inner subject interface is a string mapped interface
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				data["subject_common_name"] = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				data["subject_organizational_unit"] = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				data["subject_country"] = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				data["subject_locality"] = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				data["subject_state"] = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				data["subject_organization"] = strings.Replace(field, "O=", "", 1)
			}
		}

		temp[0] = data
		return temp
	}

	return make([]interface{}, 0)
}

func flattenMetadata(metadata interface{}, oldMetadata []interface{}) []interface{} {
	if metadata != nil {
		var newMetadataArray []interface{}
		for _, old := range oldMetadata {
			temp := old.(map[string]interface{})
			for key, value := range metadata.(map[string]interface{}) {
				if key == temp["name"] {
					temp["value"] = value
					break
				}
			}
			newMetadataArray = append(newMetadataArray, temp)
		}
		return newMetadataArray
	}
	return make([]interface{}, 0)
}

func flattenSANs(sans []keyfactor.SubjectAltNameElements) []interface{} {
	if len(sans) > 0 {
		sanInterface := make(map[string]interface{})
		var sanIP4Array []interface{}
		var sanDNSArray []interface{}
		var sanURIArray []interface{}

		for _, san := range sans {
			sanName := mapSanIDToName(san.Type)
			if sanName == "IP Address" {
				sanIP4Array = append(sanIP4Array, san.Value)
			} else if sanName == "DNS Name" {
				sanDNSArray = append(sanDNSArray, san.Value)
			} else if sanName == "Uniform Resource Identifier" {
				sanURIArray = append(sanURIArray, san.Value)
			}
		}
		// To avoid provider drift, make sure that these entries are only written if SANs were returned by Keyfactor
		if sanDNSArray != nil {
			sanInterface["san_dns"] = sanDNSArray
		}
		if sanIP4Array != nil {
			sanInterface["san_ip4"] = sanIP4Array
		}
		if sanURIArray != nil {
			sanInterface["san_uri"] = sanURIArray
		}

		ret := make([]interface{}, 1, 1)
		ret[0] = sanInterface

		return ret
	}

	return make([]interface{}, 0)
}

// mapSanIDToName maps an inputted integer value as a SAN type returned by Keyfactor API and returns the associated
// DNS type string
func mapSanIDToName(sanID int) string {
	switch sanID {
	case 0:
		return "Other Name"
	case 1:
		return "RFC 822 Name"
	case 2:
		return "DNS Name"
	case 3:
		return "X400 Address"
	case 4:
		return "Directory Name"
	case 5:
		return "Ediparty Name"
	case 6:
		return "Uniform Resource Identifier"
	case 7:
		return "IP Address"
	case 8:
		return "Registered Id"
	case 100:
		return "MS_NTPrincipalName"
	case 101:
		return "MS_NTDSReplication"
	}
	return ""
}

func downloadCertificate(id int, kfClient *keyfactor.Client, format string) (error, string) {
	downloadArgs := &keyfactor.DownloadCertArgs{
		CertID:       id,
		IncludeChain: true,
		CertFormat:   format,
	}

	resp, err := kfClient.DownloadCertificate(downloadArgs)
	if err != nil {
		return err, ""
	}
	return nil, resp.Content
}

func resourceCertificateUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClient := m.(*keyfactor.Client)

	if metadataHasChange(d) == true {
		metadata := d.Get("metadata").([]interface{})

		args := &keyfactor.UpdateMetadataArgs{
			CertID:              d.Get("keyfactor_id").(int),
			CertificateMetadata: interfaceArrayToStringTuple(metadata),
			Metadata:            nil,
			CollectionId:        0,
		}

		err := kfClient.UpdateMetadata(args)
		if err != nil {
			return diag.FromErr(err)
		}
	} else {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Failed to update keyfactor_certificate configuration.",
			Detail: "The only supported update field is Metadata. X.509 certificate attributes cannot be changed " +
				"after enrollment, please create a new keyfactor_certificate resource block.",
			AttributePath: nil,
		})
	}
	resourceCertificateRead(ctx, d, m)
	return diags
}

func metadataHasChange(d *schema.ResourceData) bool {
	metadataRootSearchTerm := "metadata"
	// Most obvious change to detect is the number of metadata schema blocks that exist.
	if d.HasChange(fmt.Sprintf("%s.#", metadataRootSearchTerm)) == true {
		return true
	}

	// Next, for each name - value pair, attempt to detect a change.
	metadataCount := d.Get(fmt.Sprintf("%s.#", metadataRootSearchTerm))
	for i := 0; i < metadataCount.(int); i++ {
		if d.HasChange(fmt.Sprintf("%s.%d.name", metadataRootSearchTerm, i)) {
			return true
		} else if d.HasChange(fmt.Sprintf("%s.%d.value", metadataRootSearchTerm, i)) {
			return true
		}
	}
	// If we got this far, it's safe to assume that we didn't experience a change.
	return false
}

func resourceCertificateDelete(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	log.Println("[INFO] Deleting certificate resource")

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.
	kfClient := m.(*keyfactor.Client)

	log.Println("[INFO] Revoking certificate in Keyfactor")
	revokeArgs := &keyfactor.RevokeCertArgs{
		CertificateIds: []int{d.Get("keyfactor_id").(int)}, // Certificate ID expects array of integers
		Reason:         5,                                  // reason = 5 means Cessation of Operation
		Comment:        "Terraform destroy called on provider with associated cert ID",
	}

	if collectionId := d.Get("collection_id"); collectionId.(int) != 0 {
		revokeArgs.CollectionId = collectionId.(int)
	}

	err := kfClient.RevokeCert(revokeArgs)
	if err != nil {
		return diag.FromErr(err)
	}

	return diags
}
