package keyfactor

import (
	"context"
	"crypto/ecdsa"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceKeyfactorCertificateType struct{}

func (r resourceKeyfactorCertificateType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"csr": {
				Type:          types.StringType,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Base-64 encoded certificate signing request (CSR)",
			},
			"key_password": {
				Type:     types.StringType,
				Optional: true,
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Sensitive:   true,
				Description: "Password used to recover the private key from Keyfactor Command. NOTE: If no value is provided a random password will be generated for key recovery. This value is not stored and does not encrypt the private key in Terraform state. Also note that if a password is provided it must meet any password complexity requirements enforced by the CA template or creation will fail. Auto-generated passwords will be of length 32 and contain a minimum of 4 of the following: uppercase, lowercase, numeric, and special characters.",
			},
			"common_name": {
				Type:     types.StringType,
				Computed: false,
				//Required:      true,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject common name (CN) of the certificate.",
			},
			"locality": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject locality (L) of the certificate",
			},
			"organization": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject organization (O) of the certificate",
			},
			"state": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject state (ST) of the certificate",
			},
			"country": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject country of the certificate",
			},
			"organizational_unit": {
				Type:          types.StringType,
				Computed:      false,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject organizational unit (OU) of the certificate",
			},
			"certificate_authority": {
				Type:          types.StringType,
				Required:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	return strings.EqualFold(old, new)
				//},
				Description: "Name of certificate authority to deploy certificate with Ex: Example Company CA 1",
			},
			"certificate_template": {
				Type:          types.StringType,
				Required:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Short name of certificate template to be deployed",
			},
			"dns_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "List of DNS names to use as subjects of the certificate. ",
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
			},
			"uri_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "List of URIs to use as subjects of the certificate. ",
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
			},
			"ip_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "List of DNS names to use as subjects of the certificate. ",
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
			},
			"metadata": {
				Type: types.MapType{
					ElemType: types.StringType,
				},
				Optional:    true,
				Description: "Metadata key-value pairs to be attached to certificate",
			},
			"serial_number": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Serial number of newly enrolled certificate",
			},
			"issuer_dn": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Issuer distinguished name that signed the certificate",
			},
			"thumbprint": {
				Type:        types.StringType,
				Computed:    true,
				Description: "Thumbprint of newly enrolled certificate",
			},
			"identifier": {
				Type:     types.StringType,
				Required: false,
				Computed: true,
				Description: "Keyfactor certificate identifier. This can be any of the following values: thumbprint, CN, " +
					"or Keyfactor Command Certificate ID. If using CN to lookup the last issued certificate, the CN must " +
					"be an exact match and if multiple certificates are returned the certificate that was most recently " +
					"issued will be returned. ",
			},
			"collection_id": {
				Type:     types.Int64Type,
				Computed: false,
				Optional: true,
				Description: "Optional certificate collection ID. This is required if enrollment permissions have been " +
					"granted at the collection level. NOTE: This will *not* assign the cert to the specified collection ID; " +
					"assignment is based the collection's associated query. For more information on collection permissions see " +
					"the Keyfactor Command docs: https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/CertificatePermissions.htm?Highlight=collection%20permissions",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"certificate_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Keyfactor Command certificate ID.",
			},
			"command_request_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Keyfactor request ID.",
			},
			"certificate_pem": {
				Type:        types.StringType,
				Computed:    true,
				Description: "PEM formatted certificate",
			},
			"ca_certificate": {
				Type:        types.StringType,
				Computed:    true,
				Description: "PEM formatted CA certificate",
			},
			"certificate_chain": {
				Type:        types.StringType,
				Computed:    true,
				Description: "PEM formatted full certificate chain",
			},
			"private_key": {
				Type:        types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "PEM formatted PKCS#1 private key imported if cert_template has KeyRetention set to a value other than None, and the certificate was not enrolled using a CSR.",
			},
			"collection_enrollment_wait": {
				Type:     types.StringType,
				Computed: false,
				Optional: true,
				Description: "The maximum time to wait for a certificate to be added to a collection, " +
					"post enrollment. This is useful for certificates that trigger issue handlers and/or workflows" +
					" post enrollment and will delay the certificate being added to the expected collection. Format" +
					": 1h, " +
					"1m, 1s. Default: 0.",
			},
		},
	}, nil
}

func (r resourceKeyfactorCertificateType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceKeyfactorCertificate{
		p: *(p.(*provider)),
	}, nil
}

type resourceKeyfactorCertificate struct {
	p provider
}

func (r resourceKeyfactorCertificate) Create(
	ctx context.Context,
	request tfsdk.CreateResourceRequest,
	response *tfsdk.CreateResourceResponse,
) {
	tflog.Info(ctx, "Create called on certificate resource")
	tflog.Debug(ctx, "Checking provider configuration")
	if !r.p.configured {
		response.Diagnostics.AddError(
			"Provider not configured",
			"The provider hasn't been configured before apply, likely because it depends on an unknown value from another resource. This leads to weird stuff happening, so we'd prefer if you didn't do that. Thanks!",
		)
		return
	}

	// Retrieve values from plan
	var plan KeyfactorCertificate
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan

	kfClient := r.p.client

	certificateId := plan.ID.Value
	collectionId := plan.CollectionId.Value
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	ctx = tflog.SetField(ctx, "collection_id", collectionId)
	tflog.Info(ctx, "Create called on certificate resource")

	//sans := plan.SANs
	//metadata := plan.Metadata.Elems
	csr := plan.CSR.Value
	// If CSR and CommonName are both set, or neither are set, error
	if (plan.CSR.IsNull() && plan.CommonName.IsNull()) || (!plan.CSR.IsNull() && !plan.CommonName.IsNull()) || (csr == "" && plan.CommonName.IsNull()) {
		tflog.Error(ctx, "Invalid resource definition, CSR and CN are both null")
		response.Diagnostics.AddError(
			ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE,
			"You must provide either a CSR or a CN to create a certificate.",
		)
		return
	}

	var dnsSANs []string
	var ipSANs []string
	var uriSANs []string
	var metadata map[string]interface{}
	tflog.Debug(ctx, fmt.Sprintf("Parsing DNS SANs: %s", plan.DNSSANs))
	diags = plan.DNSSANs.ElementsAs(ctx, &dnsSANs, true)
	tflog.Debug(ctx, fmt.Sprintf("Parsing IP SANs: %s", plan.IPSANs))
	diags = plan.IPSANs.ElementsAs(ctx, &ipSANs, true)
	tflog.Debug(ctx, fmt.Sprintf("Parsing URI SANs: %s", plan.URISANs))
	diags = plan.URISANs.ElementsAs(ctx, &uriSANs, true)
	// iterate over metadata map and convert to map[string]interface{}
	tflog.Debug(ctx, fmt.Sprintf("Parsing metadata: %s", plan.Metadata))
	metaDataElms := plan.Metadata.Elems
	metadata = make(map[string]interface{})
	for k, elm := range metaDataElms {
		metadata[k] = strings.Replace(elm.String(), "\"", "", -1)
	}

	sans := append(dnsSANs, ipSANs...)
	sans = append(sans, uriSANs...)
	ctx = tflog.SetField(ctx, "sans", sans)

	var autoPassword string
	var lookupPassword string

	if !plan.CSR.IsNull() && csr != "" { //Enroll CSR

		//ensure that conflicting values are not set
		if plan.CommonName.Value != "" || plan.Organization.Value != "" || plan.OrganizationalUnit.Value != "" || plan.Locality.Value != "" || plan.State.Value != "" || plan.Country.Value != "" || plan.PrivateKey.Value != "" || plan.KeyPassword.Value != "" {
			response.Diagnostics.AddError(
				ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE,
				"You cannot set the private_key, password, common_name, organization, organizational_unit, locality, state, or country when using a CSR.",
			)
			return
		}

		tflog.Debug(ctx, "Creating certificate from CSR.")

		tflog.Debug(ctx, fmt.Sprintf("Creating certificate with SANs: %s", sans))
		CSRArgs := &api.EnrollCSRFctArgs{
			CSR:                  csr,
			CertificateAuthority: plan.CertificateAuthority.Value,
			Template:             plan.CertificateTemplate.Value,
			IncludeChain:         true,
			CertFormat:           "PEM", // Retrieve certificate in READ
			SANs: &api.SANs{
				IP4: ipSANs,
				IP6: nil, //TODO: ipv6 SANs support
				DNS: dnsSANs,
				URI: uriSANs,
			},
			Metadata: metadata,
		}
		tflog.Trace(
			ctx, "Passing args to Keyfactor API.", map[string]interface{}{
				"args": CSRArgs,
			},
		)
		enrollResponse, err := kfClient.EnrollCSR(CSRArgs)
		if err != nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				"Could not create certificate in Keyfactor: "+err.Error(),
			)
			return
		}

		//Collection

		// iterate through CertificateInformation.Certificates and concatenate
		var (
			fullChain string
			caCert    string
			leaf      string
		)

		for i, cert := range enrollResponse.CertificateInformation.Certificates {
			// split by \r\n and remove first line if '#' is present
			if strings.Contains(cert, "#") {
				cert = strings.Join(strings.Split(cert, "\r\n")[1:], "\r\n")
			}

			fullChain += cert
			if i > 0 { //caCert returns full chain minus leaf
				caCert += cert
			} else {
				// split by \r\n and remove first line

				leaf = cert
			}
		}

		//fetch certificate from Keyfactor
		//leaf, chain, _, dErr := downloadCertificate(
		//	enrollResponse.CertificateInformation.KeyfactorID,
		//	int(collectionId),
		//	r.p.client,
		//	autoPassword,
		//	csr != "",
		//)
		//if dErr != nil {
		//	response.Diagnostics.AddError(
		//		ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
		//		fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+dErr.Error(), certificateId),
		//	)
		//	return
		//}

		// Set state
		var result = KeyfactorCertificate{
			ID: types.String{
				Value: fmt.Sprintf(
					"%v",
					enrollResponse.CertificateInformation.KeyfactorID,
				),
			},
			CSR:                  types.String{Value: csr},
			CommonName:           plan.CommonName,
			Organization:         plan.Organization,
			OrganizationalUnit:   plan.OrganizationalUnit,
			Locality:             plan.Locality,
			State:                plan.State,
			Country:              plan.Country,
			DNSSANs:              plan.DNSSANs,
			IPSANs:               plan.IPSANs,
			URISANs:              plan.URISANs,
			SerialNumber:         types.String{Value: enrollResponse.CertificateInformation.SerialNumber},
			IssuerDN:             types.String{Value: enrollResponse.CertificateInformation.IssuerDN},
			Thumbprint:           types.String{Value: enrollResponse.CertificateInformation.Thumbprint},
			PEM:                  types.String{Value: leaf},
			PEMCACert:            types.String{Value: caCert},
			PEMChain:             types.String{Value: fullChain},
			PrivateKey:           types.String{Value: plan.PrivateKey.Value, Null: true},
			KeyPassword:          types.String{Value: plan.KeyPassword.Value, Null: true},
			CertificateAuthority: plan.CertificateAuthority,
			CertificateId:        types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorID)},
			CertificateTemplate:  plan.CertificateTemplate,
			Metadata:             plan.Metadata,
			CollectionId:         plan.CollectionId,
			CollectionEnrollmentWait: types.String{
				Value: plan.CollectionEnrollmentWait.Value,
				Null:  isNullString(plan.CollectionEnrollmentWait.Value),
			},
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	} else { //Enroll PFX
		tflog.Info(ctx, "Resource is PFX certificate enrollment.")
		if plan.KeyPassword.Value == "" {
			tflog.Debug(ctx, "No password provided, generating random password.")
			autoPassword = generatePassword(
				DEFAULT_PFX_PASSWORD_LEN,
				DEFAULT_PFX_PASSWORD_SPECIAL_CHAR_COUNT,
				DEFAULT_PFX_PASSWORD_NUMBER_COUNT,
				DEFAULT_PFX_PASSWORD_UPPER_COUNT,
			)
			lookupPassword = autoPassword
		} else {
			tflog.Debug(ctx, "Password provided, using provided password.")
			lookupPassword = plan.KeyPassword.Value
		}

		tflog.Debug(ctx, "Creating API request.")
		PFXArgs := &api.EnrollPFXFctArgsV2{
			CustomFriendlyName:          plan.CommonName.Value,
			Password:                    lookupPassword,
			PopulateMissingValuesFromAD: false, //TODO: Add support for this
			CertificateAuthority:        plan.CertificateAuthority.Value,
			Template:                    plan.CertificateTemplate.Value,
			IncludeChain:                true,    //TODO: Add support for this
			CertFormat:                  "STORE", // Get certificate from data source
			SANs: &api.SANs{
				IP4: ipSANs,
				IP6: nil, //TODO: ipv6 SANs support
				DNS: dnsSANs,
				URI: uriSANs,
			},
			Metadata: metadata,
			Subject: &api.CertificateSubject{
				SubjectCommonName:         plan.CommonName.Value,
				SubjectLocality:           plan.Locality.Value,
				SubjectOrganization:       plan.Organization.Value,
				SubjectCountry:            plan.Country.Value,
				SubjectOrganizationalUnit: plan.OrganizationalUnit.Value,
				SubjectState:              plan.State.Value,
			},
		}
		tflog.Debug(ctx, "API PFXArgs created.")

		//convert PFX args to JSON string
		tflog.Debug(ctx, "Converting PFXArgs to JSON.")
		jsonData, err := json.Marshal(PFXArgs)
		if err != nil {
			tflog.Error(ctx, "Error converting PFXArgs to JSON.")
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				"Could not convert PFXArgs to JSON: "+err.Error(),
			)
			return
		}
		ctx = tflog.SetField(ctx, "pfx_args", string(jsonData))
		tflog.Debug(ctx, fmt.Sprintf("PFXArgs: %s", string(jsonData)))
		tflog.Debug(ctx, fmt.Sprintf("Creating PFX certificate %s on Keyfactor.", PFXArgs.Subject.SubjectCommonName))
		tflog.Debug(ctx, "Calling EnrollPFXV2.")
		enrollResponse, err := r.p.client.EnrollPFXV2(PFXArgs)
		if err != nil {
			tflog.Error(ctx, "No response from Keyfactor Command after PFX enrollment.")
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				fmt.Sprintf(
					"Could not create certificate %s on Keyfactor: "+err.Error(),
					PFXArgs.Subject.SubjectCommonName,
				),
			)
			return
		}
		enrolledId := enrollResponse.CertificateInformation.KeyfactorID
		ctx = tflog.SetField(ctx, "enrolled_id", enrolledId)
		enrolledThumbprint := enrollResponse.CertificateInformation.Thumbprint
		ctx = tflog.SetField(ctx, "enrolled_thumbprint", enrolledThumbprint)
		enrolledSerialNumber := enrollResponse.CertificateInformation.SerialNumber
		ctx = tflog.SetField(ctx, "enrolled_serial_number", enrolledSerialNumber)
		enrolledIssuerDN := enrollResponse.CertificateInformation.IssuerDN
		ctx = tflog.SetField(ctx, "enrolled_issuer_dn", enrolledIssuerDN)
		// check if request is pending approvals
		if enrollResponse.CertificateInformation.RequestDisposition == "PENDING" {
			// call HandlePendingCert
			tflog.Debug(ctx, fmt.Sprintf("Certificate %s is pending approval.", PFXArgs.Subject.SubjectCommonName))
			tflog.Debug(
				ctx,
				fmt.Sprintf("Calling HandlePendingCert for certificate %s.", PFXArgs.Subject.SubjectCommonName),
			)
			approvedCert, pErr := r.HandlePendingCert(
				ctx,
				enrollResponse,
				PFXArgs.Subject.SubjectCommonName,
				int(collectionId),
			)
			ERROR_PENDING_CERTS_PERMISSIONS := "does not have any of the required permissions: Alerts - Read"
			if pErr != nil {
				//check if error contains 401
				if strings.Contains(pErr.Error(), "401") || strings.Contains(
					pErr.Error(),
					ERROR_PENDING_CERTS_PERMISSIONS,
				) {
					tflog.Warn(ctx, "Unauthorized to list pending certificate requests.")
					waitResp, waitErr := r.WaitForPendingCert(
						ctx,
						enrollResponse,
						plan.CommonName.Value,
						int(collectionId),
					)
					if waitErr != nil {
						tflog.Error(
							ctx,
							fmt.Sprintf("Error handling pending certificate %s.", PFXArgs.Subject.SubjectCommonName),
						)
						response.Diagnostics.AddError(
							ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
							fmt.Sprintf(
								"Could not create certificate '%s' on Keyfactor Command: "+pErr.Error(),
								PFXArgs.Subject.SubjectCommonName,
							),
						)
						return
					}
					approvedCert = waitResp
				} else {
					tflog.Error(
						ctx,
						fmt.Sprintf("Error handling pending certificate %s.", PFXArgs.Subject.SubjectCommonName),
					)
					response.Diagnostics.AddError(
						ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
						fmt.Sprintf(
							"Could not create certificate '%s' on Keyfactor Command: "+pErr.Error(),
							PFXArgs.Subject.SubjectCommonName,
						),
					)
					return
				}
			}
			if approvedCert == nil {
				tflog.Error(
					ctx,
					fmt.Sprintf("Certificate '%s' is pending approval.", PFXArgs.Subject.SubjectCommonName),
				)
				response.Diagnostics.AddError(
					ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
					fmt.Sprintf(
						"No response recieved on create certificate '%s' on Keyfactor Command: "+pErr.Error(),
						PFXArgs.Subject.SubjectCommonName,
					),
				)
				return
			}

			enrolledId = approvedCert.Id
			ctx = tflog.SetField(ctx, "enrolled_id", enrolledId)
			enrolledThumbprint = approvedCert.Thumbprint
			ctx = tflog.SetField(ctx, "enrolled_thumbprint", enrolledThumbprint)
			enrolledSerialNumber = approvedCert.SerialNumber
			ctx = tflog.SetField(ctx, "enrolled_serial_number", enrolledSerialNumber)
			enrolledIssuerDN = approvedCert.IssuerDN
			ctx = tflog.SetField(ctx, "enrolled_issuer_dn", enrolledIssuerDN)
			tflog.Info(
				ctx,
				fmt.Sprintf(
					"Certificate %s (%d) has been approved and created.",
					PFXArgs.Subject.SubjectCommonName,
					enrolledId,
				),
			)
		}

		// Download and assign certificates to proper location
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Downloading certificate '%s'(%d) from Keyfactor Command.",
				PFXArgs.Subject.SubjectCommonName,
				enrolledId,
			),
		)
		tflog.Debug(ctx, "Calling downloadCertificate")
		maxColletionWait, wErr := parseDuration(plan.CollectionEnrollmentWait.Value)
		if wErr != nil {
			maxColletionWait = 0
		}
		leaf, chain, pKey, dErr := downloadCertificate(
			enrolledId,
			int(collectionId),
			r.p.client,
			lookupPassword,
			csr != "",
			maxColletionWait,
		)
		if dErr != nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+dErr.Error(), certificateId),
			)
		}
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Certificate '%s'(%d) has been downloaded from Keyfactor Command.",
				PFXArgs.Subject.SubjectCommonName,
				enrolledId,
			),
		)

		fullChain := leaf + chain
		// Set state
		tflog.Info(
			ctx,
			fmt.Sprintf("Setting state for certificate '%s'(%d).", PFXArgs.Subject.SubjectCommonName, enrolledId),
		)
		tflog.Debug(ctx, "Creating state object")
		var result = KeyfactorCertificate{
			ID:                   types.String{Value: fmt.Sprintf("%v", enrolledId)},
			CSR:                  plan.CSR,
			CommonName:           plan.CommonName,
			Organization:         plan.Organization,
			OrganizationalUnit:   plan.OrganizationalUnit,
			Locality:             plan.Locality,
			State:                plan.State,
			Country:              plan.Country,
			DNSSANs:              plan.DNSSANs,
			IPSANs:               plan.IPSANs,
			URISANs:              plan.URISANs,
			SerialNumber:         types.String{Value: enrolledSerialNumber},
			IssuerDN:             types.String{Value: enrolledIssuerDN},
			Thumbprint:           types.String{Value: enrolledThumbprint},
			PEM:                  types.String{Value: leaf},
			PEMCACert:            types.String{Value: chain},
			PEMChain:             types.String{Value: fullChain},
			PrivateKey:           types.String{Value: pKey},
			KeyPassword:          plan.KeyPassword,
			CertificateAuthority: plan.CertificateAuthority,
			CertificateTemplate:  plan.CertificateTemplate,
			CertificateId:        types.Int64{Value: int64(enrolledId)},
			RequestId:            types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorRequestID)},
			Metadata:             plan.Metadata,
			CollectionId:         plan.CollectionId,
			CollectionEnrollmentWait: types.String{
				Value: plan.CollectionEnrollmentWait.Value,
				Null:  isNullString(plan.CollectionEnrollmentWait.Value),
			},
		}

		tflog.Debug(ctx, "Setting state")
		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}
	}

}

func (r resourceKeyfactorCertificate) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	tflog.Info(ctx, "Read called on certificate resource")
	var state KeyfactorCertificate
	tflog.Debug(ctx, "Reading state file")
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading state file")
		return
	}

	tflog.Debug(ctx, "Parsing certificate ID")
	certificateIdInt, cIdErr := strconv.Atoi(state.ID.Value)
	if cIdErr != nil {
		tflog.Error(ctx, "Error parsing certificate ID, setting to -1")
		certificateIdInt = -1
	}
	var (
		certificateCN         string
		certificateThumbprint string
	)
	// Check if certificateID is a thumbprint or CN
	if certificateIdInt == -1 {
		tflog.Debug(ctx, "Certificate ID is not an integer, checking if it is a thumbprint or CN")
		if len(state.ID.Value) == 40 {
			tflog.Info(ctx, fmt.Sprintf("Certificate ID '%v' is a thumbprint.", state.ID.Value))
			certificateThumbprint = state.ID.Value
		} else {
			tflog.Info(ctx, fmt.Sprintf("Certificate ID '%v' is a CN.", state.ID.Value))
			certificateCN = state.ID.Value
		}
	}

	collectionID := state.CollectionId.Value
	collectionIdInt := int(collectionID)

	ctx = tflog.SetField(ctx, "collection_id", collectionID)
	ctx = tflog.SetField(ctx, "certificate_id", certificateIdInt)
	ctx = tflog.SetField(ctx, "certificate_cn", certificateCN)
	ctx = tflog.SetField(ctx, "certificate_thumbprint", certificateThumbprint)

	tflog.Info(ctx, fmt.Sprintf("Attempting to lookup certificate '%v' in Keyfactor.", state.ID.Value))
	tflog.Debug(ctx, "Calling GetCertificateContextArgs")
	args := &api.GetCertificateContextArgs{
		IncludeMetadata:      boolToPointer(true),
		IncludeLocations:     boolToPointer(true),
		IncludeHasPrivateKey: boolToPointer(true),
		CollectionId:         intToPointer(collectionIdInt),
		Id:                   certificateIdInt,
		CommonName:           certificateCN,
		Thumbprint:           certificateThumbprint,
	}

	tflog.Debug(ctx, "Calling GetCertificateContext")
	cResp, err := r.p.client.GetCertificateContext(args)
	if err != nil {
		tflog.Error(ctx, "Error calling GetCertificateContext")
		response.Diagnostics.AddWarning(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+err.Error(), state.ID.Value),
		)
		nullValue := types.String{Null: true}
		nullList := types.List{Null: true, ElemType: types.StringType}
		emptyResult := KeyfactorCertificate{
			ID:                 nullValue,
			CSR:                nullValue,
			CommonName:         nullValue,
			Locality:           nullValue,
			State:              nullValue,
			Country:            nullValue,
			Organization:       nullValue,
			OrganizationalUnit: nullValue,
			DNSSANs:            nullList,
			IPSANs:             nullList,
			URISANs:            nullList,
			SerialNumber:       nullValue,
			IssuerDN:           nullValue,
			Thumbprint:         nullValue,
			PEM:                nullValue,
			PEMCACert:          nullValue,
			PEMChain:           nullValue,
			PrivateKey:         nullValue,
			KeyPassword:        state.KeyPassword,
			//PEM:                  state.PEM,
			//PEMChain:             state.PEMChain,
			//PrivateKey:           state.PrivateKey,
			//KeyPassword:          state.KeyPassword,
			CertificateAuthority: nullValue,
			CertificateTemplate:  nullValue,
			Metadata:             types.Map{Null: true, ElemType: types.StringType},
			CertificateId:        types.Int64{Null: true},
			CollectionId:         types.Int64{Null: true},
			CollectionEnrollmentWait: types.String{
				Value: state.CollectionEnrollmentWait.Value,
				Null:  isNullString(state.CollectionEnrollmentWait.Value),
			},
		}
		diags = response.State.Set(ctx, &emptyResult)
		response.Diagnostics.Append(diags...)
		return
	}

	// Get the password out of current schema
	csr := state.CSR.Value

	// Download and assign certificates to proper location
	//leaf, chain, pKey, dErr := downloadCertificate(certificateIdInt, r.p.client, state.KeyPassword.Value, csr != "")
	// check if state has an auto password
	lookupPassword := state.KeyPassword.Value
	if lookupPassword == "" {
		tflog.Debug(ctx, "No password provided, generating random password.")
		lookupPassword = generatePassword(
			DEFAULT_PFX_PASSWORD_LEN,
			DEFAULT_PFX_PASSWORD_SPECIAL_CHAR_COUNT,
			DEFAULT_PFX_PASSWORD_NUMBER_COUNT,
			DEFAULT_PFX_PASSWORD_UPPER_COUNT,
		)
	}
	tflog.Info(
		ctx,
		fmt.Sprintf("Downloading certificate '%s'(%d) from Keyfactor Command.", state.ID.Value, certificateIdInt),
	)

	_, _, _, dErr := downloadCertificate(certificateIdInt, collectionIdInt, r.p.client, lookupPassword, csr != "", 0)
	if dErr != nil {
		tflog.Error(ctx, "Error downloading certificate from Keyfactor Command.")
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+dErr.Error(), state.ID.Value),
		)
	}

	tflog.Debug(ctx, "Calling expandSubject")
	cn, ou, o, l, st, c := expandSubject(cResp.IssuedDN)
	tflog.Debug(ctx, "Calling flattenSANs")
	dnsSans, ipSans, uriSans := flattenSANs(cResp.SubjectAltNameElements, state.DNSSANs, state.IPSANs, state.URISANs)
	ctx = tflog.SetField(ctx, "dns_sans", dnsSans)
	ctx = tflog.SetField(ctx, "ip_sans", ipSans)
	ctx = tflog.SetField(ctx, "uri_sans", uriSans)

	var (
		leaf  string
		chain = ""
		pKey  = ""
	)

	if cResp.HasPrivateKey {
		tflog.Info(ctx, "Requested certificate has a private key attempting to recover from Keyfactor Command.")
		tflog.Debug(ctx, "Calling RecoverCertificate")
		//pKeyO, _, chainO, dErrO := r.p.client.RecoverCertificate(cResp.Id, "", "", "", lookupPassword)
		pKeyO, _, chainO, dErrO := r.p.client.RecoverCertificate(cResp.Id, "", "", "", lookupPassword, collectionIdInt)
		if dErrO != nil {
			tflog.Error(
				ctx,
				fmt.Sprintf("Unable to recover private key for certificate '%v' from Keyfactor Command.", cResp.Id),
			)
			response.Diagnostics.AddError(
				"Error recovering private key from Keyfactor Command.",
				fmt.Sprintf(
					"Could not retrieve private key for certificate '%s' from Keyfactor Command: "+dErrO.Error(),
					cResp.Id,
				),
			)
			return
		}
		tflog.Info(ctx, "Recovered private key from Keyfactor Command.")
		tflog.Debug(ctx, "Decoding certificate response")
		lBytes, lbErr := base64.StdEncoding.DecodeString(cResp.ContentBytes)
		if lbErr != nil {
			tflog.Error(ctx, "Error decoding certificate content bytes.")
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf(
					"Could not retrieve certificate '%s' from Keyfactor Command: "+lbErr.Error(),
					state.ID.Value,
				),
			)
			return
		}
		tflog.Debug(ctx, "Decoding leaf cert.")
		leaf = string(
			pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: lBytes,
				},
			),
		)
		tflog.Debug(ctx, "Recovered leaf certificate from Keyfactor Command:")
		tflog.Debug(ctx, leaf)
		tflog.Debug(ctx, "Recovered certificate chain from Keyfactor Command:")
		for i, cert := range chainO {
			tflog.Debug(ctx, fmt.Sprintf("Decoding chain cert %d", i))
			chainLink := string(
				pem.EncodeToMemory(
					&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: cert.Raw,
					},
				),
			)
			chain += chainLink
			tflog.Debug(ctx, chainLink)
		}

		tflog.Debug(ctx, "Recovered private key from Keyfactor Command:")
		tflog.Debug(ctx, "Attempting RSA private key recovery")
		rsa, ok := pKeyO.(*rsa2.PrivateKey)
		if ok {
			tflog.Debug(ctx, "Recovered RSA private key from Keyfactor Command:")
			buf := x509.MarshalPKCS1PrivateKey(rsa)
			if len(buf) > 0 {
				tflog.Debug(ctx, "Encoding RSA private key from Keyfactor Command.")
				pKey = string(
					pem.EncodeToMemory(
						&pem.Block{
							Bytes: buf,
							Type:  "RSA PRIVATE KEY",
						},
					),
				)
				tflog.Trace(ctx, pKey)
			} else {
				tflog.Debug(ctx, "Empty Key Recovered from Keyfactor Command.")
			}
		} else {
			tflog.Debug(ctx, "Attempting ECC private key recovery")
			ecc, ok := pKeyO.(*ecdsa.PrivateKey)
			if ok {
				// We don't really care about the error here. An error just means that the key will be blank which isn't a
				// reason to fail
				tflog.Debug(ctx, "Recovered ECC private key from Keyfactor Command:")
				buf, _ := x509.MarshalECPrivateKey(ecc)
				if len(buf) > 0 {
					tflog.Debug(ctx, "Encoding ECC private key from Keyfactor Command.")
					pKey = string(
						pem.EncodeToMemory(
							&pem.Block{
								Bytes: buf,
								Type:  "EC PRIVATE KEY",
							},
						),
					)
					tflog.Trace(ctx, pKey)
				}
			}
		}
	} else {
		// Convert string to []byte and then to pem.
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Requested certificate '%s'(%d) does not have a private key in Keyfactor Command.",
				state.ID.Value,
				certificateIdInt,
			),
		)
		tflog.Debug(ctx, "Decoding certificate response")
		lBytes, lbErr := base64.StdEncoding.DecodeString(cResp.ContentBytes)
		if lbErr != nil {
			tflog.Error(ctx, "Error decoding certificate content bytes.")
			tflog.Error(ctx, lbErr.Error())
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf(
					"Could not retrieve certificate '%s' from Keyfactor Command: "+lbErr.Error(),
					state.ID.Value,
				),
			)
			return
		}

		tflog.Debug(ctx, "Decoding leaf cert.")
		leaf = string(
			pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: lBytes,
				},
			),
		)
		tflog.Debug(ctx, "Recovered leaf certificate from Keyfactor Command:")
		tflog.Debug(ctx, leaf)

		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Attempting to download certificate '%s'(%d) chain from Keyfactor Command.",
				state.ID.Value,
				certificateIdInt,
			),
		)
		tflog.Debug(ctx, "Calling downloadCertificate")
		dlf, dChain, _, dChainErr := downloadCertificate(
			certificateIdInt,
			collectionIdInt,
			r.p.client,
			lookupPassword,
			csr != "",
			0,
		)
		//leaf, chain, pKey, dErr := downloadCertificate(enrolledId, int(collectionId), r.p.client, lookupPassword, csr != "")
		if dChainErr != nil {
			tflog.Error(ctx, "Error downloading certificate chain from Keyfactor Command.")
			response.Diagnostics.AddWarning(
				"Certificate Download Error",
				fmt.Sprintf(
					"Could not dowload certificate '%s' from Keyfactor. Chain will not be included: %s",
					state.ID.Value,
					dChainErr.Error(),
				),
			)
		}
		tflog.Trace(ctx, fmt.Sprintf("Downloaded certificate chain from Keyfactor Command:\n%s%s", dlf, dChain))
	}

	tflog.Debug(ctx, "Calling  flattenMetadata")
	metadata := flattenMetadata(cResp.Metadata)

	if len(state.Metadata.Elems) == 0 && len(metadata.Elems) == 0 {
		tflog.Debug(ctx, "Both state and Keyfactor Command metadata are empty.")
		// If both are empty then use whatever state is telling you about the value being null
		metadata.Null = state.Metadata.Null
	}

	/*
		fix issuer_dn to match create response:
		For some reason Command returns w/ spaces on create and w/o spaces on get.
		It's safer to add spaces between commas rather than trim all spaces as CNs can have spaces.
	*/
	tflog.Debug(ctx, "Fixing issuer_dn")
	issuerDN := strings.Replace(cResp.IssuerDN, ",", ", ", -1)

	fullChain := leaf + chain
	var result = KeyfactorCertificate{}
	if state.CSR.Value != "" {
		tflog.Debug(ctx, "Creating state object for certificate with CSR.")
		result = KeyfactorCertificate{
			ID:                 types.String{Value: fmt.Sprintf("%v", cResp.Id)},
			CSR:                types.String{Value: csr, Null: isNullString(csr)},
			CommonName:         types.String{Value: cn.Value, Null: true},
			Locality:           types.String{Value: l.Value, Null: true},
			State:              types.String{Value: st.Value, Null: true},
			Country:            types.String{Value: c.Value, Null: true},
			Organization:       types.String{Value: o.Value, Null: true},
			OrganizationalUnit: types.String{Value: ou.Value, Null: true},
			DNSSANs:            state.DNSSANs,
			IPSANs:             state.IPSANs,
			URISANs:            state.URISANs,
			SerialNumber:       types.String{Value: cResp.SerialNumber, Null: isNullString(cResp.SerialNumber)},
			IssuerDN:           types.String{Value: issuerDN, Null: isNullString(issuerDN)},
			Thumbprint:         types.String{Value: cResp.Thumbprint, Null: isNullString(cResp.Thumbprint)},
			PEM:                types.String{Value: leaf, Null: isNullString(leaf)},
			PEMCACert:          types.String{Value: chain, Null: isNullString(chain)},
			PEMChain:           types.String{Value: fullChain, Null: isNullString(fullChain)},
			PrivateKey:         state.PrivateKey,
			KeyPassword:        state.KeyPassword,
			//PEM:                  state.PEM,
			//PEMChain:             state.PEMChain,
			//PrivateKey:           state.PrivateKey,
			//KeyPassword:          state.KeyPassword,
			CertificateAuthority: types.String{
				Value: cResp.CertificateAuthorityName,
				Null:  isNullString(cResp.CertificateAuthorityName),
			},
			CertificateTemplate: state.CertificateTemplate,
			Metadata:            metadata,
			CertificateId:       types.Int64{Value: int64(cResp.Id), Null: isNullId(cResp.Id)},
			CollectionId:        types.Int64{Value: int64(collectionIdInt), Null: isNullId(collectionIdInt)},
			CollectionEnrollmentWait: types.String{
				Value: state.CollectionEnrollmentWait.Value,
				Null:  isNullString(state.CollectionEnrollmentWait.Value),
			},
		}
	} else {
		tflog.Debug(ctx, "Creating state object for certificate PFX.")
		result = KeyfactorCertificate{
			ID:                 types.String{Value: fmt.Sprintf("%v", cResp.Id)},
			CSR:                types.String{Value: csr, Null: isNullString(csr)},
			CommonName:         cn,
			Locality:           types.String{Value: l.Value, Null: isNullString(l.Value)},
			State:              types.String{Value: st.Value, Null: isNullString(st.Value)},
			Country:            types.String{Value: c.Value, Null: isNullString(c.Value)},
			Organization:       types.String{Value: o.Value, Null: isNullString(o.Value)},
			OrganizationalUnit: types.String{Value: ou.Value, Null: isNullString(ou.Value)},
			DNSSANs:            dnsSans,
			IPSANs:             ipSans,
			URISANs:            uriSans,
			SerialNumber:       types.String{Value: cResp.SerialNumber, Null: isNullString(cResp.SerialNumber)},
			IssuerDN:           types.String{Value: issuerDN, Null: isNullString(issuerDN)},
			Thumbprint:         types.String{Value: cResp.Thumbprint, Null: isNullString(cResp.Thumbprint)},
			PEM:                types.String{Value: leaf, Null: isNullString(leaf)},
			PEMCACert:          types.String{Value: chain, Null: isNullString(chain)},
			PEMChain:           types.String{Value: fullChain, Null: isNullString(fullChain)},
			PrivateKey:         types.String{Value: pKey, Null: isNullString(pKey)},
			KeyPassword:        state.KeyPassword,
			//PEM:                  state.PEM,
			//PEMChain:             state.PEMChain,
			//PrivateKey:           state.PrivateKey,
			//KeyPassword:          state.KeyPassword,
			CertificateAuthority: types.String{
				Value: cResp.CertificateAuthorityName,
				Null:  isNullString(cResp.CertificateAuthorityName),
			},
			CertificateTemplate: state.CertificateTemplate,
			Metadata:            metadata,
			CertificateId:       types.Int64{Value: int64(cResp.Id), Null: isNullId(cResp.Id)},
			CollectionId:        state.CollectionId,
			CollectionEnrollmentWait: types.String{
				Value: state.CollectionEnrollmentWait.Value,
				Null:  isNullString(state.CollectionEnrollmentWait.Value),
			},
		}
	}

	// Set state
	tflog.Debug(ctx, "Setting state")
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceKeyfactorCertificate) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	tflog.Info(ctx, "Update called on certificate resource")
	// Get plan values
	var plan KeyfactorCertificate
	tflog.Debug(ctx, "Reading plan file")
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading plan file")
		return
	}

	// Get current state
	var state KeyfactorCertificate
	tflog.Debug(ctx, "Reading state file")
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Debug(ctx, "Error reading state file")
		return
	}

	csr := plan.CSR.Value

	if (plan.CSR.IsNull() && plan.CommonName.IsNull()) || (!plan.CSR.IsNull() && !plan.CommonName.IsNull()) || (csr == "" && plan.CommonName.IsNull()) {
		tflog.Error(
			ctx,
			"Invalid certificate resource definition, must provide either a CSR or a CN to create a certificate",
		)
		response.Diagnostics.AddError(
			ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE,
			"You must provide either a CSR or a CN to create a certificate.",
		)
		return
	}

	if csr != "" {
		tflog.Debug(ctx, "Creating certificate from CSR.")

		var dnsSANs []string
		var ipSANs []string
		var uriSANs []string
		var planMetadata map[string]string
		var stateMetadata map[string]string
		diags = state.DNSSANs.ElementsAs(ctx, &dnsSANs, true)
		diags = state.IPSANs.ElementsAs(ctx, &ipSANs, true)
		diags = state.URISANs.ElementsAs(ctx, &uriSANs, true)
		diags = plan.Metadata.ElementsAs(ctx, &planMetadata, false)
		diags = state.Metadata.ElementsAs(ctx, &stateMetadata, false)

		//diags = request.Plan.Get(ctx, &metadata)

		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}

		certificateIdInt, cIdErr := strconv.Atoi(plan.ID.Value)
		if cIdErr != nil {
			certificateIdInt = -1
		}

		sans := append(dnsSANs, ipSANs...)
		sans = append(sans, uriSANs...)

		tflog.Debug(ctx, fmt.Sprintf("Creating certificate with SANs: %s", sans))
		metaInterface := make(map[string]interface{})
		for k, v := range planMetadata {
			metaInterface[k] = v
		}
		if !plan.Metadata.Equal(state.Metadata) {
			tflog.Debug(ctx, "Metadata is updated. Attempting to update metadata on Keyfactor.")
			metadataReq := &api.UpdateMetadataArgs{
				CertID:   certificateIdInt,
				Metadata: metaInterface,
			}
			if plan.CollectionId.Value > 0 {
				metadataReq.CollectionId = int(plan.CollectionId.Value)
			}
			err := r.p.client.UpdateMetadata(
				metadataReq,
			)
			if err != nil {
				response.Diagnostics.AddError(
					"Certificate metadata update error.",
					fmt.Sprintf("Could not update cert '%s''s metadata on Keyfactor: "+err.Error(), state.ID.Value),
				)
				return
			}

		}

		// Set state
		var result = KeyfactorCertificate{
			ID:                       types.String{Value: state.ID.Value},
			CSR:                      plan.CSR,
			CommonName:               plan.CommonName,
			Locality:                 plan.Locality,
			State:                    plan.State,
			Country:                  plan.Country,
			Organization:             plan.Organization,
			OrganizationalUnit:       plan.OrganizationalUnit,
			DNSSANs:                  plan.DNSSANs,
			IPSANs:                   plan.IPSANs,
			URISANs:                  plan.URISANs,
			SerialNumber:             plan.SerialNumber,
			IssuerDN:                 plan.IssuerDN,
			Thumbprint:               plan.Thumbprint,
			PEM:                      plan.PEM,
			PEMCACert:                plan.PEMChain,
			PEMChain:                 types.String{Value: fmt.Sprintf("%s%s", plan.PEM.Value, plan.PEMChain.Value)},
			PrivateKey:               plan.PrivateKey,
			KeyPassword:              plan.KeyPassword,
			CertificateAuthority:     plan.CertificateAuthority,
			CertificateTemplate:      plan.CertificateTemplate,
			Metadata:                 plan.Metadata,
			CollectionId:             plan.CollectionId,
			CollectionEnrollmentWait: plan.CollectionEnrollmentWait,
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	} else {
		//check if metadata is updated
		var planMetadata map[string]string
		var stateMetadata map[string]string
		tflog.Debug(ctx, "Reading metadata from state and plan")
		diags = plan.Metadata.ElementsAs(ctx, &planMetadata, false)
		tflog.Debug(ctx, "Reading metadata from state and plan")
		diags = state.Metadata.ElementsAs(ctx, &stateMetadata, false)

		if !plan.Metadata.Equal(state.Metadata) {
			tflog.Debug(ctx, "Metadata is updated. Attempting to update metadata on Keyfactor.")

			// Convert map[string]string to map[string]interface{}
			planMetadataInterface := make(map[string]interface{})
			for k, v := range planMetadata {
				tflog.Trace(ctx, fmt.Sprintf("Setting metadata key %s to value %s", k, v))
				planMetadataInterface[k] = v
			}
			tflog.Info(ctx, fmt.Sprintf("Updating metadata for certificate '%s' on Keyfactor Command.", state.ID.Value))
			updateReq := &api.UpdateMetadataArgs{
				CertID:   int(state.CertificateId.Value),
				Metadata: planMetadataInterface,
			}
			if plan.CollectionId.Value > 0 {
				tflog.Debug(ctx, "Setting collection ID on API request")
				updateReq.CollectionId = int(plan.CollectionId.Value)
			}
			err := r.p.client.UpdateMetadata(updateReq)
			if err != nil {
				response.Diagnostics.AddError(
					"Certificate metadata update error.",
					fmt.Sprintf("Could not update cert '%s''s metadata on Keyfactor: "+err.Error(), state.ID.Value),
				)
				return
			}
		}

		// Set state
		tflog.Debug(ctx, "Creating KeyfactorCertificate state object")
		var result = KeyfactorCertificate{
			ID:                       state.ID,
			CSR:                      state.CSR,
			CommonName:               state.CommonName,
			Locality:                 state.Locality,
			State:                    state.State,
			Country:                  state.Country,
			Organization:             state.Organization,
			OrganizationalUnit:       state.OrganizationalUnit,
			DNSSANs:                  state.DNSSANs,
			IPSANs:                   state.IPSANs,
			URISANs:                  state.URISANs,
			SerialNumber:             state.SerialNumber,
			IssuerDN:                 state.IssuerDN,
			Thumbprint:               state.Thumbprint,
			PEM:                      state.PEM,
			PEMCACert:                state.PEMCACert,
			PEMChain:                 state.PEMChain,
			PrivateKey:               state.PrivateKey,
			KeyPassword:              plan.KeyPassword,
			CertificateId:            state.CertificateId,
			CertificateAuthority:     state.CertificateAuthority,
			CertificateTemplate:      state.CertificateTemplate,
			Metadata:                 plan.Metadata,
			CollectionId:             state.CollectionId,
			CollectionEnrollmentWait: plan.CollectionEnrollmentWait,
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}
	}
}

func (r resourceKeyfactorCertificate) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on certificate resource")
	var state KeyfactorCertificate
	tflog.Debug(ctx, "Reading state file")
	diags := request.State.Get(ctx, &state)
	kfClient := r.p.client

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading state file")
		return
	}

	// Get order ID from state
	certificateId := state.ID.Value
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)

	if certificateId == "" {
		tflog.Warn(ctx, "Certificate ID is empty, removing empty certificate from state.")
		response.Diagnostics.AddWarning(
			"Certificate ID is empty.",
			"Delete called on empty ID. Removing empty certificate from state.",
		)
		response.State.RemoveResource(ctx)
		return
	}

	tflog.Debug(ctx, "Parsing certificate ID")
	certificateIdInt, cIdErr := strconv.Atoi(state.ID.Value)
	tflog.Debug(ctx, "Parsing certificate CN")
	certificateCN := state.CommonName.Value
	tflog.Debug(ctx, "Parsing certificate thumbprint")
	certificateThumbprint := state.Thumbprint.Value
	if cIdErr != nil {
		if certificateThumbprint == "" && certificateCN == "" {
			tflog.Error(ctx, "Invalid Certificate ID")
			response.Diagnostics.AddError(
				"Invalid Certificate ID",
				"Certificate ID is not an integer, unable to call revoke API.",
			)
		}
		return
	}

	collectionID := state.CollectionId.Value
	collectionIdInt := int(collectionID)

	ctx = tflog.SetField(ctx, "collection_id", collectionID)
	ctx = tflog.SetField(ctx, "certificate_id", certificateIdInt)
	ctx = tflog.SetField(ctx, "certificate_cn", certificateCN)
	ctx = tflog.SetField(ctx, "certificate_thumbprint", certificateThumbprint)

	tflog.Info(ctx, fmt.Sprintf("Revoking certificate %v on Keyfactor Command", certificateId))

	tflog.Debug(ctx, "Creating RevokeCertArgs")
	revokeArgs := &api.RevokeCertArgs{
		CertificateIds: []int{certificateIdInt}, // Certificate ID expects array of integers
		Reason:         5,                       // reason = 5 means Cessation of Operation
		Comment:        "Terraform destroy called on provider with associated cert ID",
	}

	if collectionIdInt > 0 {
		tflog.Debug(ctx, "Setting collection ID on API request")
		revokeArgs.CollectionId = collectionIdInt
	}

	tflog.Debug(ctx, "Calling RevokeCert")
	err := kfClient.RevokeCert(revokeArgs)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error revoking certificate '%d' on Keyfactor Command", certificateIdInt))
		response.Diagnostics.AddError(
			"Certificate revocation error.",
			fmt.Sprintf("Could not revoke cert '%s' on Keyfactor: "+err.Error(), certificateId),
		)
	}

	// Remove resource from state
	tflog.Debug(ctx, "Removing certificate from state")
	response.State.RemoveResource(ctx)
	tflog.Info(ctx, fmt.Sprintf("Certificate '%s' removed from state.", certificateId))
}

func (r resourceKeyfactorCertificate) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on certificate resource")
	var state KeyfactorCertificate
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate resource")
	certificateId := request.ID
	certificateIdInt, err := strconv.Atoi(certificateId)
	if err != nil {
		response.Diagnostics.AddError(
			"Import error.",
			fmt.Sprintf("Could not convert cert ID '%s' to integer: "+err.Error(), certificateId),
		)
		return
	}

	tflog.SetField(ctx, "certificate_id", certificateId)

	// Get certificate context
	tflog.Debug(ctx, "Creating GetCertificateContextArgs object")
	args := &api.GetCertificateContextArgs{
		IncludeMetadata:  boolToPointer(true),
		IncludeLocations: boolToPointer(true),
		CollectionId:     nil,
		Id:               certificateIdInt,
	}
	tflog.Info(ctx, fmt.Sprintf("Attempting to retrieve certificate '%s' from Keyfactor Command.", certificateId))
	//todo: support for collection ID
	tflog.Debug(ctx, "Calling GetCertificateContext")
	certificateData, err := r.p.client.GetCertificateContext(args)
	if err != nil {
		tflog.Error(
			ctx,
			fmt.Sprintf("Error retrieving certificate '%s' from Keyfactor Command: "+err.Error(), certificateId),
		)
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+err.Error(), certificateId),
		)
		return
	}

	// Get the password out of current schema
	password := ""
	csr := ""

	// Download and assign certificates to proper location
	tflog.Info(
		ctx,
		fmt.Sprintf(
			"Downloading certificate '%s'(%d) from Keyfactor Command.",
			certificateData.IssuedCN,
			certificateData.Id,
		),
	)
	tflog.Debug(ctx, "Calling downloadCertificate")
	leaf, chain, priv, dErr := downloadCertificate(
		certificateData.Id,
		0,
		r.p.client,
		password,
		csr != "",
		0,
	) // add support for importing with collection ID
	if dErr != nil {
		tflog.Error(
			ctx,
			fmt.Sprintf("Error downloading certificate '%s' from Keyfactor Command: "+dErr.Error(), certificateId),
		)
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+dErr.Error(), certificateId),
		)
		return
	}

	tflog.Debug(ctx, "Creating KeyfactorCertificate object")
	var result = KeyfactorCertificate{
		ID:                   types.String{Value: state.ID.Value},
		CSR:                  types.String{Value: csr},
		CommonName:           state.CommonName,
		Locality:             state.Locality,
		State:                state.State,
		Country:              state.Country,
		Organization:         state.Organization,
		OrganizationalUnit:   state.OrganizationalUnit,
		DNSSANs:              state.DNSSANs,
		IPSANs:               state.IPSANs,
		URISANs:              state.URISANs,
		SerialNumber:         state.SerialNumber,
		IssuerDN:             state.IssuerDN,
		Thumbprint:           state.Thumbprint,
		PEM:                  types.String{Value: leaf},
		PEMChain:             types.String{Value: chain},
		PrivateKey:           types.String{Value: priv},
		KeyPassword:          types.String{Value: password},
		CertificateAuthority: state.CertificateAuthority,
		CertificateTemplate:  state.CertificateTemplate,
		Metadata:             state.Metadata,
	}

	// Set state
	tflog.Debug(ctx, "Setting state")
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error setting state")
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Certificate '%s' imported into state.", certificateId))
}

func (r resourceKeyfactorCertificate) CertLookupByRequestID(
	ctx context.Context,
	requestID int,
	collectionId int,
) (*api.GetCertificateResponse, error) {
	certArgs := &api.GetCertificateContextArgs{
		IncludeMetadata:      boolToPointer(true),
		IncludeLocations:     boolToPointer(true),
		IncludeHasPrivateKey: boolToPointer(true),
		CollectionId:         intToPointer(collectionId),
		Id:                   0,
		CommonName:           "",
		Thumbprint:           "",
		RequestId:            requestID,
	}
	certResp, err := r.p.client.GetCertificateContext(certArgs)
	if err != nil {
		return nil, err
	}
	return certResp, nil
}

func (r resourceKeyfactorCertificate) WaitForPendingCert(
	ctx context.Context,
	enrollResponse *api.EnrollResponseV2,
	cn string,
	collectionId int,
) (*api.GetCertificateResponse, error) {
	tflog.Debug(ctx, "Enter WaitForPendingCert")
	sleepDuration := 1 * time.Second
	isPending := true
	ctx = tflog.SetField(ctx, "certificate_request_id", enrollResponse.CertificateInformation.KeyfactorRequestID)
	ctx = tflog.SetField(ctx, "common_name", cn)
	ctx = tflog.SetField(ctx, "sleep_duration", sleepDuration)
	ctx = tflog.SetField(ctx, "is_pending", isPending)
	tflog.Info(ctx, "Waiting for certificate request to be approved.")

	for i := 0; i < MAX_ITERATIONS; i++ {
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Certificate %d for %s is pending approvals, waiting on approval.",
				enrollResponse.CertificateInformation.KeyfactorRequestID,
				cn,
			),
		)
		tflog.Debug(ctx, "Looking for a certificate with request ID on Keyfactor Command")
		certResp, err := r.CertLookupByRequestID(
			ctx,
			enrollResponse.CertificateInformation.KeyfactorRequestID,
			collectionId,
		)
		if err != nil {
			tflog.Error(
				ctx,
				fmt.Sprintf(
					"Error looking up certificate with request ID %d on Keyfactor Command: "+err.Error(),
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			// increment sleep duration
			tflog.Debug(ctx, fmt.Sprintf("Sleeping for %v", sleepDuration))
			time.Sleep(sleepDuration)
			sleepDuration *= SLEEP_DURATION_MULTIPLIER
			if sleepDuration > MAX_WAIT_SECONDS*time.Second {
				sleepDuration = MAX_WAIT_SECONDS * time.Second
			}
			continue
		}
		if certResp != nil && certResp.CertRequestId == enrollResponse.CertificateInformation.KeyfactorRequestID {
			tflog.Info(
				ctx,
				fmt.Sprintf(
					"Certificate '%s' found with request ID '%d' so approval must have occurred.",
					cn,
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			return certResp, nil
		}
		// increment sleep duration
		tflog.Debug(ctx, fmt.Sprintf("Sleeping for %v", sleepDuration))
		time.Sleep(sleepDuration)
		sleepDuration *= SLEEP_DURATION_MULTIPLIER
		if sleepDuration > MAX_WAIT_SECONDS*time.Second {
			sleepDuration = MAX_WAIT_SECONDS * time.Second
		}
	}
	tflog.Warn(
		ctx,
		fmt.Sprintf(
			"Certificate request '%d' for '%s' is still pending approvals after '%d' iterations",
			enrollResponse.CertificateInformation.KeyfactorRequestID,
			cn,
			MAX_ITERATIONS,
		),
	)
	return nil, fmt.Errorf(
		"certificate request '%d' for '%s' is still pending approvals, waiting on approval",
		enrollResponse.CertificateInformation.KeyfactorRequestID,
		cn,
	)
}

func (r resourceKeyfactorCertificate) HandlePendingCert(
	ctx context.Context,
	enrollResponse *api.EnrollResponseV2,
	cn string,
	collectionId int,
) (*api.GetCertificateResponse, error) {
	tflog.Info(ctx, "Certificate is pending approval, waiting on approval.")
	tflog.Debug(ctx, "Enter HandlePendingCert")
	sleepDuration := 1 * time.Second
	isPending := true
	ctx = tflog.SetField(ctx, "certificate_id", enrollResponse.CertificateInformation.KeyfactorRequestID)
	ctx = tflog.SetField(ctx, "common_name", cn)
	ctx = tflog.SetField(ctx, "sleep_duration", sleepDuration)
	ctx = tflog.SetField(ctx, "is_pending", isPending)
	for i := 0; i < MAX_ITERATIONS; i++ {
		tflog.Info(
			ctx,
			fmt.Sprintf(
				"Certificate %d for %s is pending approvals, waiting on approval.",
				enrollResponse.CertificateInformation.KeyfactorRequestID,
				cn,
			),
		)

		tflog.Debug(ctx, "Fetching pending certificates from Keyfactor Command")
		pendingCertsResponse, lpErr := r.p.client.ListPendingCertificates(nil) //todo: can I pass collection ID?

		tflog.Debug(ctx, "Fetching certificates pending external validation from Keyfactor Command")
		pendingExternalResponse, lpeErr := r.p.client.ListExternalValidationPendingCertificates(nil) //todo: can I pass collection ID?

		if lpErr != nil || lpeErr != nil {
			if lpErr != nil {
				return nil, fmt.Errorf("Could not retrieve pending certificates from Keyfactor Command: " + lpErr.Error())
			}
			return nil, fmt.Errorf("Could not retrieve pending certificates from Keyfactor Command: " + lpeErr.Error())
		}

		if isPending {
			tflog.Debug(
				ctx,
				"Iterating through pending certificates from Keyfactor Command to check if certificate is still pending",
			)
			if len(pendingCertsResponse) > 0 || len(pendingExternalResponse) > 0 {
				tflog.Debug(ctx, "Iterating through certificates pending internal validation from Keyfactor Command")
				for _, cert := range pendingCertsResponse {
					if cert.Id == enrollResponse.CertificateInformation.KeyfactorRequestID {
						tflog.Info(
							ctx,
							fmt.Sprintf(
								"Certificate %d for %s is pending approvals, waiting on approval for %ss.",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								cn,
								sleepDuration,
							),
						)
						tflog.Debug(ctx, fmt.Sprintf("Sleeping for %v", sleepDuration))
						time.Sleep(sleepDuration)
						sleepDuration *= SLEEP_DURATION_MULTIPLIER
						tflog.Debug(ctx, "Incrementing sleep duration for next loop")
						if sleepDuration > MAX_WAIT_SECONDS*time.Second {
							sleepDuration = MAX_WAIT_SECONDS * time.Second
						}
						isPending = true
						tflog.Debug(
							ctx,
							fmt.Sprintf(
								"Certificate %d is still pending approvals, sleeping for %v",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								sleepDuration,
							),
						)
						break
					}
					tflog.Debug(
						ctx,
						fmt.Sprintf(
							"Certificate %d is not pending internal approvals",
							enrollResponse.CertificateInformation.KeyfactorRequestID,
						),
					)
					isPending = false
				}
			} else {
				if i < MAX_APPROVAL_WAIT_LOOPS {
					tflog.Debug(
						ctx,
						"No pending certificates from Keyfactor Command checking if approval has occurred.",
					)
					approveResp, _ := r.CertLookupByRequestID(
						ctx,
						enrollResponse.CertificateInformation.KeyfactorRequestID,
						collectionId,
					) //todo: pass collection ID
					if approveResp != nil && approveResp.CertRequestId == enrollResponse.CertificateInformation.KeyfactorRequestID {
						tflog.Debug(ctx, "Certificate found so approval must have occurred.")
						return approveResp, nil
					}

					tflog.Debug(ctx, "Allowing time for Keyfactor Command to generate certificate approval.")
					tflog.Info(
						ctx,
						fmt.Sprintf(
							"No pending certificates from Keyfactor Command, will check again in %d seconds.",
							sleepDuration,
						),
					)
					time.Sleep(sleepDuration)
					sleepDuration *= SLEEP_DURATION_MULTIPLIER
					continue
				}
				tflog.Debug(
					ctx,
					"No pending certificates from Keyfactor Command so this approval or denial must have occurred.",
				)
				isPending = false
			}
			if !isPending {
				tflog.Debug(ctx, "Iterating through certificates pending external validation from Keyfactor Command")
				for _, cert := range pendingExternalResponse {
					if cert.Id == enrollResponse.CertificateInformation.KeyfactorRequestID {
						tflog.Info(
							ctx,
							fmt.Sprintf(
								"Certificate %d for %s is pending approvals, waiting on approval for %ss.",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								cn,
								sleepDuration,
							),
						)
						time.Sleep(sleepDuration)
						sleepDuration *= SLEEP_DURATION_MULTIPLIER
						if sleepDuration > MAX_WAIT_SECONDS*time.Second {
							sleepDuration = MAX_WAIT_SECONDS * time.Second
						}
						isPending = true
						tflog.Debug(
							ctx,
							fmt.Sprintf(
								"Certificate %d is still pending approvals, sleeping for %v",
								enrollResponse.CertificateInformation.KeyfactorRequestID,
								sleepDuration,
							),
						)
						break
					}
					tflog.Debug(
						ctx,
						fmt.Sprintf(
							"Certificate %d is not pending external approvals",
							enrollResponse.CertificateInformation.KeyfactorRequestID,
						),
					)
					isPending = false
				}
			}
		}
		if !isPending {
			tflog.Info(
				ctx,
				fmt.Sprintf(
					"Certificate %d is not pending approvals, checking if it was denied",
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			deniedCertsResponse, _ := r.p.client.ListDeniedCertificates(nil)
			for _, cert := range deniedCertsResponse {
				if cert.Id == enrollResponse.CertificateInformation.KeyfactorRequestID {
					errMsg := fmt.Sprintf(
						"Certificate request '%d' for %s was denied ",
						enrollResponse.CertificateInformation.KeyfactorRequestID,
						cn,
					)
					tflog.Error(ctx, errMsg)
					return nil, fmt.Errorf(errMsg)
				}
			}
			tflog.Info(
				ctx,
				fmt.Sprintf(
					"Certificate %d is not pending approvals, checking if it was approved",
					enrollResponse.CertificateInformation.KeyfactorRequestID,
				),
			)
			time.Sleep(MAX_WAIT_SECONDS * time.Second) // Allow command to generate cert
			break
		}
	}
	// Look up certificate by certjficate request ID and return the most recently issued certificate
	certResponse, gErr := r.CertLookupByRequestID(
		ctx,
		enrollResponse.CertificateInformation.KeyfactorRequestID,
		collectionId,
	)
	if gErr != nil {
		return nil, gErr
	}
	return certResponse, nil
}
