package keyfactor

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/m8rmclaren/keyfactor_go_client/pkg/keyfactor"
	"strconv"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceCertificateCreate,
		ReadContext:   resourceCertificateRead,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,
		Schema: map[string]*schema.Schema{
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
			"metadata": &schema.Schema{
				Type:        schema.TypeList,
				Optional:    true,
				Description: "",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
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
			"csr": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base-64 encoded certificate signing request (CSR)",
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
	}
}

func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	csr := d.Get("csr").(string)
	kfClientData := m.(*keyfactor.APIClient)

	if csr != "" { // If a CSR is provided, enroll the CSR and return it
		CSRArgs := &keyfactor.EnrollCSRFctArgs{
			CSR:                  d.Get("csr").(string),
			CertificateAuthority: d.Get("certificate_authority").(string),
			Template:             d.Get("cert_template").(string),
			IncludeChain:         d.Get("include_chain").(bool),
			CertFormat:           d.Get("certificate_format").(string),
			CertificateSANs:      buildSANStruct(d),
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
			CustomFriendlyName:          d.Get("friendly_name").(string),
			KeyPassword:                 d.Get("key_password").(string),
			PopulateMissingValuesFromAD: d.Get("populate_missing_values_from_ad").(bool),
			CertificateAuthority:        d.Get("certificate_authority").(string),
			Template:                    d.Get("cert_template").(string),
			IncludeChain:                d.Get("include_chain").(bool),
			RenewalCertificateId:        d.Get("renewal_certificate_id").(int),
			CertFormat:                  d.Get("certificate_format").(string),
			CertificateSANs:             buildSANStruct(d), // if no SANs are specified, this field is nil
			CertificateSubject: keyfactor.CertificateSubject{
				SubjectCommonName:         d.Get("subject_common_name").(string),
				SubjectLocality:           d.Get("subject_locality").(string),
				SubjectOrganization:       d.Get("subject_organization").(string),
				SubjectCountry:            d.Get("subject_country").(string),
				SubjectOrganizationalUnit: d.Get("subject_organizational_unit").(string),
				SubjectState:              d.Get("subject_state").(string),
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
	return diags
}

func buildSANStruct(d *schema.ResourceData) *keyfactor.SANs {
	// Look for IP4 SANs
	sans := &keyfactor.SANs{}
	sansAdded := 0
	ip4San, added := createSANStringArray(d, "san_ip4")
	if added > 0 {
		sans.IP4 = ip4San
		sansAdded++
	}
	ip6San, added := createSANStringArray(d, "san_ip6")
	if added > 0 {
		sans.IP6 = ip6San
		sansAdded++
	}
	dnsSan, added := createSANStringArray(d, "san_dns")
	if added > 0 {
		sans.DNS = dnsSan
		sansAdded++
	}
	uriSan, added := createSANStringArray(d, "san_uri")
	if added > 0 {
		sans.URI = uriSan
		sansAdded++
	}
	if sansAdded == 0 {
		return nil
	}
	return sans
}

func createSANStringArray(d *schema.ResourceData, searchKey string) ([]string, int) {
	var temp []string
	i := 0
	size := d.Get(fmt.Sprintf("%s.#", searchKey)).(int) // Get number of SANs user entered in schema
	if size > 0 {
		for i = 0; i < size; i++ {
			key := fmt.Sprintf("%s.%d", searchKey, i) // Get SAN values using "<key>.<element>" notation
			sanKey := d.Get(key)
			temp = append(temp, sanKey.(string))
		}
	}
	return temp, i // return a string array and the number of elements added
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
