package provider

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/pkg/keyfactor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceCertificateCreate,
		ReadContext:   resourceCertificateRead,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,
		Schema: map[string]*schema.Schema{
			"certificate": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
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
							Required:    true,
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
							Type:        schema.TypeString,
							Required:    true,
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
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"san_uri": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of IPv6 addresses to use as subjects of the certificate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"san_dns": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of DNS names to use as subjects of the certificate",
										Elem:        &schema.Schema{Type: schema.TypeString},
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
						"deployment": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "PFX certificate deployment options (certificate format must be STORE)",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"store_ids": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of store IDs to deploy PFX certificate into",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"store_type_ids": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "List of store IDs to deploy PFX certificate into",
										Elem:        &schema.Schema{Type: schema.TypeInt},
									},
									"alias": {
										Type:        schema.TypeList,
										Optional:    true,
										Description: "Alias that certificate will be stored under in new certificate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
								},
							},
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
						"pkcs12": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "PKCS#12 formatted certificate",
						},
					},
				},
			},
		},
	}
}

func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	kfClient := m.(*keyfactor.Client)

	certificates := d.Get("certificate").([]interface{})

	for _, certificate := range certificates {
		i := certificate.(map[string]interface{})
		subject := i["subject"].([]interface{})[0].(map[string]interface{}) // Extract subject data from schema
		sans := i["sans"].([]interface{})                                   // Extract SANs from schema
		metadata := i["metadata"].([]interface{})

		var deploy = false
		if len(i["deployment"].([]interface{})) > 0 {
			deploy = true // If deployment options are set to true, deploy the certificate
		}

		if i["csr"] != "" {
			CSRArgs := &keyfactor.EnrollCSRFctArgs{
				CSR:                  i["csr"].(string),
				CertificateAuthority: i["certificate_authority"].(string),
				Template:             i["cert_template"].(string),
				IncludeChain:         i["include_chain"].(bool),
				CertFormat:           "STORE", // Retrieve certificate in READ
				CertificateSANs:      getSans(sans),
				CertificateMetadata:  interfaceArrayToStringTuple(metadata),
			}
			enrollResponse, err := kfClient.EnrollCSR(CSRArgs)
			if err != nil {
				return diag.FromErr(err)
			}

			// Set resource ID to tell Terraform that operation was successful*
			d.SetId(strconv.Itoa(enrollResponse.CertificateInformation.KeyfactorID))

			resourceCertificateRead(ctx, d, m) // populate terraform state to current state after creation
		} else {
			PFXArgs := &keyfactor.EnrollPFXFctArgs{
				CustomFriendlyName:          "Terraform",
				KeyPassword:                 i["key_password"].(string),
				PopulateMissingValuesFromAD: false,
				CertificateAuthority:        i["certificate_authority"].(string),
				Template:                    i["cert_template"].(string),
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
				return diag.FromErr(err)
			}

			// Set resource ID to tell Terraform that operation was successful
			d.SetId(strconv.Itoa(enrollResponse.CertificateInformation.KeyfactorID))

			// If deployment options were provided by user, deploy the certificate
			if deploy == true {
				deploymentOptions := i["deployment"].([]interface{})

				// Extract store IDs, alias', and store type IDs from Schema. The length of these should be equal
				storeIdsInterface := deploymentOptions[0].(map[string]interface{})["store_ids"].([]interface{})
				aliasInterface := deploymentOptions[0].(map[string]interface{})["alias"].([]interface{})
				storeTypeIdsInterface := deploymentOptions[0].(map[string]interface{})["store_type_ids"].([]interface{})

				// Check if the correct number of arguments were specified to deploy the certificate (should all be equal)
				if len(storeIdsInterface) != len(aliasInterface) || len(aliasInterface) != len(storeTypeIdsInterface) {
					deployFailureString := fmt.Sprintf("Store IDs provided: %d - Store alias' provided: %d - Store type IDs provided: %d", len(storeIdsInterface), len(aliasInterface), len(storeTypeIdsInterface))
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Warning,
						Summary:  "Not enough information provided to deploy certificate.",
						Detail:   deployFailureString,
					})
					// Just becuase we failed to deploy doesn't mean that the create failed.
				} else {
					// Build []string of store IDs from interface

					deployStoreIds := make([]string, len(storeIdsInterface), len(storeIdsInterface))
					for i, id := range storeIdsInterface {
						deployStoreIds[i] = id.(string)
					}

					// Build []string of alias' from interface
					aliasArray := make([]string, len(aliasInterface), len(aliasInterface))
					for i, alias := range aliasInterface {
						aliasArray[i] = alias.(string)
					}

					// Build []StoreTypes of store type from interface
					storeTypes := make([]keyfactor.StoreTypes, len(storeTypeIdsInterface), len(storeTypeIdsInterface))
					for i, id := range storeTypeIdsInterface {
						storeTypes[i] = keyfactor.StoreTypes{
							StoreTypeId: id.(int),
							Alias:       stringToPointer(aliasArray[i]),
						}
					}

					deployPFXArgs := &keyfactor.DeployPFXArgs{
						StoreIds:      deployStoreIds,
						Password:      i["key_password"].(string),
						StoreTypes:    storeTypes,
						CertificateId: enrollResponse.CertificateInformation.KeyfactorID,
						RequestId:     enrollResponse.CertificateInformation.KeyfactorRequestID,
						JobTime:       nil,
					}

					deployResp, err := kfClient.DeployPFXCertificate(deployPFXArgs)
					if err != nil {
						return diag.FromErr(err)
					}

					if len(deployResp.FailedStores) != 0 {
						var failedStoresString string

						for _, failedStore := range deployResp.FailedStores {
							failedStoresString += failedStore + ", "
						}

						diags = append(diags, diag.Diagnostic{
							Severity: diag.Warning,
							Summary:  "Failed to deploy to one or more certificate stores",
							Detail:   failedStoresString,
						})
					}
				}
			}

			resourceCertificateRead(ctx, d, m) // populate terraform state to current state after creation
		}
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
	schemaState := d.Get("certificate").([]interface{})
	password := schemaState[0].(map[string]interface{})["key_password"].(string)

	// Download and assign certificates to proper location
	err, pem := recoverCertificate(certificateData.Id, password, kfClient, "PEM")
	if err != nil {
		return diag.FromErr(err)
	}
	err, pkcs12 := recoverCertificate(certificateData.Id, password, kfClient, "PFX")
	if err != nil {
		return diag.FromErr(err)
	}

	certificateItems := flattenCertificateItems(certificateData, kfClient, pem, pkcs12, password) // Set schema
	if err := d.Set("certificate", certificateItems); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func flattenCertificateItems(certificateContext *keyfactor.GetCertificateResponse, kfClient *keyfactor.Client, pem string, pkcs12 string, password string) []interface{} {
	if certificateContext != nil {
		temp := make([]interface{}, 1, 1)
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
			return make([]interface{}, 0)
		}
		data["cert_template"] = templates.CommonName
		data["certificate_authority"] = certificateContext.CertificateAuthorityName

		// Assign schema that require flattening
		data["sans"] = flattenSANs(certificateContext.SubjectAltNameElements)
		data["metadata"] = flattenMetadata(certificateContext.Metadata)
		data["subject"] = flattenSubject(certificateContext.IssuedDN)

		// Schema set by passed in values
		data["certificate_pem"] = pem
		data["pkcs12"] = pkcs12
		data["key_password"] = password

		temp[0] = data
		return temp
	}
	return make([]interface{}, 0)
}

func recoverCertificate(id int, password string, kfClient *keyfactor.Client, format string) (error, string) {
	recoverArgs := &keyfactor.RecoverCertArgs{
		CertId:       id,
		Password:     password,
		IncludeChain: true,
		CertFormat:   format,
	}

	resp, err := kfClient.RecoverCertificate(recoverArgs)
	if err != nil {
		return err, ""
	}
	return nil, resp.PFX
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

func flattenMetadata(metadata interface{}) []interface{} {
	if metadata != nil {
		var metadataArray []interface{}
		for key, value := range metadata.(map[string]interface{}) {
			temp := make(map[string]interface{})

			temp["name"] = key
			temp["value"] = value

			metadataArray = append(metadataArray, temp)
		}
		return metadataArray
	}
	return make([]interface{}, 0)
}

func flattenSANs(sans []keyfactor.SubjectAltNameElements) []interface{} {
	if sans != nil {
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
		sanInterface["san_dns"] = sanDNSArray
		sanInterface["san_ip4"] = sanIP4Array
		sanInterface["san_uri"] = sanURIArray

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

func resourceCertificateUpdate(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	return diags
}

func resourceCertificateDelete(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	log.Println("[INFO] Deleting certificate resource")

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.
	kfClient := m.(*keyfactor.Client)

	certificates := d.Get("certificate").([]interface{})

	for _, certificate := range certificates {
		i := certificate.(map[string]interface{})
		// Only revoke if revoke_on_destroy is true
		log.Println("[INFO] Revoking certificate in Keyfactor")
		revokeArgs := &keyfactor.RevokeCertArgs{
			CertificateIds: []int{i["keyfactor_id"].(int)}, // Certificate ID expects array of integers
			Reason:         5,                              // reason = 5 means Cessation of Operation
			Comment:        "Terraform destroy called on provider with associated cert ID",
			CollectionId:   i["collection_id"].(int),
		}

		err := kfClient.RevokeCert(revokeArgs)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	return diags
}
