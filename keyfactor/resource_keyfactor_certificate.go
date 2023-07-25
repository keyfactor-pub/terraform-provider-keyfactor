package keyfactor

import (
	"context"
	"crypto/ecdsa"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"log"
	"strconv"
	"strings"
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
				Type:          types.StringType,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Sensitive:     true,
				Description:   "Password to protect certificate and private key with",
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
				Description:   "List of DNS names to use as subjects of the certificate",
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
				Description:   "List of URIs to use as subjects of the certificate",
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
				Description:   "List of DNS names to use as subjects of the certificate",
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
				Type:        types.Int64Type,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Optional certificate collection identifier used to ensure user access to the certificate.",
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
			"certificate_chain": {
				Type:        types.StringType,
				Computed:    true,
				Description: "PEM formatted certificate chain",
			},
			"private_key": {
				Type:        types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "PEM formatted PKCS#1 private key imported if cert_template has KeyRetention set to a value other than None, and the certificate was not enrolled using a CSR.",
			},
		},
	}, nil
}

func (r resourceKeyfactorCertificateType) NewResource(_ context.Context, p tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return resourceKeyfactorCertificate{
		p: *(p.(*provider)),
	}, nil
}

type resourceKeyfactorCertificate struct {
	p provider
}

func (r resourceKeyfactorCertificate) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
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
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)
	tflog.Info(ctx, "Create called on certificate resource")

	//sans := plan.SANs
	//metadata := plan.Metadata.Elems
	csr := plan.CSR.Value
	// If CSR and CommonName are both set, or neither are set, error
	if (plan.CSR.IsNull() && plan.CommonName.IsNull()) || (!plan.CSR.IsNull() && !plan.CommonName.IsNull()) || (csr == "" && plan.CommonName.IsNull()) {
		response.Diagnostics.AddError(
			"Invalid certificate resource definition.",
			"You must provide either a CSR or a CN to create a certificate.",
		)
		return
	}

	var dnsSANs []string
	var ipSANs []string
	var uriSANs []string
	var metadata map[string]interface{}
	diags = plan.DNSSANs.ElementsAs(ctx, &dnsSANs, true)
	diags = plan.IPSANs.ElementsAs(ctx, &ipSANs, true)
	diags = plan.URISANs.ElementsAs(ctx, &uriSANs, true)
	// iterate over metadata map and convert to map[string]interface{}
	metaDataElms := plan.Metadata.Elems
	metadata = make(map[string]interface{})
	for k, elm := range metaDataElms {
		metadata[k] = strings.Replace(elm.String(), "\"", "", -1)
	}

	sans := append(dnsSANs, ipSANs...)
	sans = append(sans, uriSANs...)

	if !plan.CSR.IsNull() && csr != "" { //Enroll CSR
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
		tflog.Trace(ctx, "Passing args to Keyfactor API.", map[string]interface{}{
			"args": CSRArgs,
		})
		enrollResponse, err := kfClient.EnrollCSR(CSRArgs)
		if err != nil {
			response.Diagnostics.AddError(
				"Error creating certificate.",
				"Could not create certificate in Keyfactor: "+err.Error(),
			)
			return
		}

		//Collection

		// Set state
		var result = KeyfactorCertificate{
			ID:                   types.String{Value: fmt.Sprintf("%v", enrollResponse.CertificateInformation.KeyfactorID)},
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
			PEM:                  types.String{Value: enrollResponse.CertificateInformation.Certificates[0]},
			PEMChain:             types.String{Value: enrollResponse.CertificateInformation.Certificates[1]},
			PrivateKey:           types.String{Value: plan.PrivateKey.Value},
			KeyPassword:          plan.KeyPassword,
			CertificateAuthority: plan.CertificateAuthority,
			CertificateId:        types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorID)},
			CertificateTemplate:  plan.CertificateTemplate,
			Metadata:             plan.Metadata,
			CollectionId:         types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorID)}, //TODO: Make this collection ID
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	} else { //Enroll PFX
		PFXArgs := &api.EnrollPFXFctArgs{
			CustomFriendlyName:          plan.CommonName.Value,
			Password:                    plan.KeyPassword.Value,
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
		tflog.Debug(ctx, fmt.Sprintf("Creating PFX certificate %s on Keyfactor.", PFXArgs.Subject.SubjectCommonName))
		enrollResponse, err := kfClient.EnrollPFX(PFXArgs)
		if err != nil {
			response.Diagnostics.AddError(
				"Error creating certificate.",
				fmt.Sprintf("Could not create certificate %s on Keyfactor: "+err.Error(), PFXArgs.Subject.SubjectCommonName),
			)
			return
		}

		enrolledId := enrollResponse.CertificateInformation.KeyfactorID
		// Download and assign certificates to proper location
		leaf, chain, pKey, dErr := downloadCertificate(enrolledId, r.p.client, plan.KeyPassword.Value, csr != "")
		if dErr != nil {
			response.Diagnostics.AddError(
				"Error reading Keyfactor certificate.",
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErr.Error(), certificateId),
			)
		}

		// Set state
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
			SerialNumber:         types.String{Value: enrollResponse.CertificateInformation.SerialNumber},
			IssuerDN:             types.String{Value: enrollResponse.CertificateInformation.IssuerDN},
			Thumbprint:           types.String{Value: enrollResponse.CertificateInformation.Thumbprint},
			PEM:                  types.String{Value: leaf},
			PEMChain:             types.String{Value: chain},
			PrivateKey:           types.String{Value: pKey},
			KeyPassword:          plan.KeyPassword,
			CertificateAuthority: plan.CertificateAuthority,
			CertificateTemplate:  plan.CertificateTemplate,
			CertificateId:        types.Int64{Value: int64(enrolledId)},
			RequestId:            types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorRequestID)},
			Metadata:             plan.Metadata,
			CollectionId:         types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorRequestID)}, //TODO: Make this collection ID
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	}

}

func (r resourceKeyfactorCertificate) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	var state KeyfactorCertificate
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	//tflog.Info(ctx, "Read called on certificate resource")
	//certificateId := state.ID.Value
	//certificateIdInt := int(certificateId)
	//
	//tflog.SetField(ctx, "certificate_id", certificateId)
	// determine if certificateID is an int or string
	// if int, then it is a Keyfactor Command Certificate ID
	// if string, then it is a certificate thumbprint or CN
	certificateIdInt, cIdErr := strconv.Atoi(state.ID.Value)
	if cIdErr != nil {
		certificateIdInt = -1
	}
	var (
		certificateCN         string
		certificateThumbprint string
	)
	// Check if certificateID is a thumbprint or CN
	if certificateIdInt == -1 {
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

	tflog.SetField(ctx, "collection_id", collectionID)
	tflog.SetField(ctx, "certificate_id", certificateIdInt)
	tflog.SetField(ctx, "certificate_cn", certificateCN)
	tflog.SetField(ctx, "certificate_thumbprint", certificateThumbprint)

	tflog.Info(ctx, fmt.Sprintf("Attempting to lookup certificate '%v' in Keyfactor.", state.ID.Value))
	tflog.Debug(ctx, "Calling Keyfactor GO Client GetCertificateContext")
	args := &api.GetCertificateContextArgs{
		IncludeMetadata:  boolToPointer(true),
		IncludeLocations: boolToPointer(true),
		CollectionId:     intToPointer(collectionIdInt),
		Id:               certificateIdInt,
		CommonName:       certificateCN,
		Thumbprint:       certificateThumbprint,
	}

	cResp, err := r.p.client.GetCertificateContext(args)
	if err != nil {
		tflog.Error(ctx, "Error calling Keyfactor Go Client GetCertificateContext")
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+err.Error(), state.ID.Value),
		)
		return
	}

	// Get the password out of current schema
	csr := state.CSR.Value

	// Download and assign certificates to proper location
	//leaf, chain, pKey, dErr := downloadCertificate(certificateIdInt, r.p.client, state.KeyPassword.Value, csr != "")
	_, _, _, dErr := downloadCertificate(certificateIdInt, r.p.client, state.KeyPassword.Value, csr != "")
	if dErr != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErr.Error(), state.ID.Value),
		)
	}

	cn, ou, o, l, st, c := expandSubject(cResp.IssuedDN)
	dnsSans, ipSans, uriSans := flattenSANs(cResp.SubjectAltNameElements)

	var (
		leaf  string
		chain = ""
		pKey  = ""
	)

	if cResp.HasPrivateKey && state.KeyPassword.Value != "" {
		tflog.Info(ctx, "Requested certificate has a private key attempting to recover from Keyfactor Command.")
		pKeyO, _, chainO, dErrO := r.p.client.RecoverCertificate(cResp.Id, "", "", "", state.KeyPassword.Value)
		if dErrO != nil {
			tflog.Error(ctx, fmt.Sprintf("Unable to recover private key for certificate '%v' from Keyfactor Command.", cResp.Id))
			response.Diagnostics.AddError(
				"Error recovering private key from Keyfactor Command.",
				fmt.Sprintf("Could not retrieve private key for certificate '%s' from Keyfactor Command: "+dErrO.Error(), cResp.Id),
			)
			return
		}
		// Convert string to []byte and then to pem.
		//leaf = string(pem.EncodeToMemory(&pem.Block{
		//	Type:  "CERTIFICATE",
		//	Bytes: leafO.Raw,
		//}))
		lBytes, lbErr := base64.StdEncoding.DecodeString(cResp.ContentBytes)
		if lbErr != nil {
			response.Diagnostics.AddError(
				"Error reading Keyfactor certificate.",
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+lbErr.Error(), state.ID.Value),
			)
			return
		}
		leaf = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: lBytes,
		}))
		tflog.Debug(ctx, "Recovered leaf certificate from Keyfactor Command:")
		tflog.Debug(ctx, leaf)
		tflog.Debug(ctx, "Recovered certificate chain from Keyfactor Command:")
		for _, cert := range chainO {
			chainLink := string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}))
			chain = chain + chainLink
			tflog.Debug(ctx, chainLink)
		}

		tflog.Debug(ctx, "Recovered private key from Keyfactor Command:")
		tflog.Debug(ctx, "Attempting RSA private key recovery")
		rsa, ok := pKeyO.(*rsa2.PrivateKey)
		if ok {
			tflog.Debug(ctx, "Recovered RSA private key from Keyfactor Command:")
			buf := x509.MarshalPKCS1PrivateKey(rsa)
			if len(buf) > 0 {
				pKey = string(pem.EncodeToMemory(&pem.Block{
					Bytes: buf,
					Type:  "RSA PRIVATE KEY",
				}))
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
					pKey = string(pem.EncodeToMemory(&pem.Block{
						Bytes: buf,
						Type:  "EC PRIVATE KEY",
					}))
					tflog.Trace(ctx, pKey)
				}
			}
		}
	} else {
		// Convert string to []byte and then to pem.
		tflog.Debug(ctx, "Requested certificate does not have a private key in Keyfactor Command.")
		lBytes, lbErr := base64.StdEncoding.DecodeString(cResp.ContentBytes)
		if lbErr != nil {
			tflog.Error(ctx, "Error decoding certificate content bytes.")
			tflog.Error(ctx, lbErr.Error())
			response.Diagnostics.AddError(
				"Error reading Keyfactor certificate.",
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+lbErr.Error(), state.ID.Value),
			)
			return
		}

		tflog.Debug(ctx, "Decoding leaf cert.")
		leaf = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: lBytes,
		}))
		tflog.Debug(ctx, "Recovered leaf certificate from Keyfactor Command:")
		tflog.Debug(ctx, leaf)
	}

	metadata := flattenMetadata(cResp.Metadata)

	/*
		fix issuer_dn to match create response:
		For some reason Command returns w/ spaces on create and w/o spaces on get.
		It's safer to add spaces between commas rather than trim all spaces as CNs can have spaces.
	*/

	issuerDN := strings.Replace(cResp.IssuerDN, ",", ", ", -1)

	var result = KeyfactorCertificate{
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
		PEMChain:           types.String{Value: chain, Null: isNullString(chain)},
		PrivateKey:         types.String{Value: pKey, Null: isNullString(pKey)},
		KeyPassword:        types.String{Value: state.KeyPassword.Value, Null: isNullString(state.KeyPassword.Value)},
		//PEM:                  state.PEM,
		//PEMChain:             state.PEMChain,
		//PrivateKey:           state.PrivateKey,
		//KeyPassword:          state.KeyPassword,
		CertificateAuthority: types.String{
			Value: cResp.CertificateAuthorityName,
			Null:  isNullString(cResp.CertificateAuthorityName),
		},
		CertificateTemplate: types.String{Value: cResp.TemplateName, Null: isNullString(cResp.TemplateName)},
		Metadata:            metadata,
		CertificateId:       types.Int64{Value: int64(cResp.Id), Null: isNullId(cResp.Id)},
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceKeyfactorCertificate) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	// Get plan values
	var plan KeyfactorCertificate
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state KeyfactorCertificate
	diags = request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	csr := plan.CSR.Value

	if (plan.CSR.IsNull() && plan.CommonName.IsNull()) || (!plan.CSR.IsNull() && !plan.CommonName.IsNull()) || (csr == "" && plan.CommonName.IsNull()) {
		response.Diagnostics.AddError(
			"Invalid certificate resource definition.",
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

			err := r.p.client.UpdateMetadata(
				&api.UpdateMetadataArgs{
					CertID:   certificateIdInt,
					Metadata: metaInterface,
				})
			if err != nil {
				response.Diagnostics.AddError("Certificate metadata update error.", fmt.Sprintf("Could not update cert '%s''s metadata on Keyfactor: "+err.Error(), state.ID.Value))
				return
			}

		}

		// Set state
		var result = KeyfactorCertificate{
			ID:                   types.String{Value: state.ID.Value},
			CSR:                  plan.CSR,
			CommonName:           plan.CommonName,
			Locality:             plan.Locality,
			State:                plan.State,
			Country:              plan.Country,
			Organization:         plan.Organization,
			OrganizationalUnit:   plan.OrganizationalUnit,
			DNSSANs:              plan.DNSSANs,
			IPSANs:               plan.IPSANs,
			URISANs:              plan.URISANs,
			SerialNumber:         plan.SerialNumber,
			IssuerDN:             plan.IssuerDN,
			Thumbprint:           plan.Thumbprint,
			PEM:                  plan.PEM,
			PEMChain:             plan.PEMChain,
			PrivateKey:           plan.PrivateKey,
			KeyPassword:          plan.KeyPassword,
			CertificateAuthority: plan.CertificateAuthority,
			CertificateTemplate:  plan.CertificateTemplate,
			Metadata:             plan.Metadata,
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
		diags = plan.Metadata.ElementsAs(ctx, &planMetadata, false)
		diags = state.Metadata.ElementsAs(ctx, &stateMetadata, false)

		if !plan.Metadata.Equal(state.Metadata) {
			tflog.Debug(ctx, "Metadata is updated. Attempting to update metadata on Keyfactor.")

			// Convert map[string]string to map[string]interface{}
			planMetadataInterface := make(map[string]interface{})
			for k, v := range planMetadata {
				planMetadataInterface[k] = v
			}
			err := r.p.client.UpdateMetadata(
				&api.UpdateMetadataArgs{
					CertID:   int(state.CertificateId.Value),
					Metadata: planMetadataInterface,
				})
			if err != nil {
				response.Diagnostics.AddError("Certificate metadata update error.", fmt.Sprintf("Could not update cert '%s''s metadata on Keyfactor: "+err.Error(), state.ID.Value))
				return
			}

		}

		// Set state
		var result = KeyfactorCertificate{
			ID:                   types.String{Value: state.ID.Value},
			CSR:                  state.CSR,
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
			PEM:                  state.PEM,
			PEMChain:             state.PEMChain,
			PrivateKey:           state.PrivateKey,
			KeyPassword:          state.KeyPassword,
			CertificateAuthority: state.CertificateAuthority,
			CertificateTemplate:  state.CertificateTemplate,
			Metadata:             plan.Metadata,
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	}
}

func (r resourceKeyfactorCertificate) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	var state KeyfactorCertificate
	diags := request.State.Get(ctx, &state)
	kfClient := r.p.client

	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// Get order ID from state
	certificateId := state.ID.Value
	tflog.SetField(ctx, "certificate_id", certificateId)

	certificateIdInt, cIdErr := strconv.Atoi(state.ID.Value)
	if cIdErr != nil {
		certificateIdInt = -1
	}

	// Delete order by calling API
	log.Println("[INFO] Deleting certificate resource")

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.

	tflog.Info(ctx, fmt.Sprintf("Revoking certificate %v in Keyfactor", certificateId))

	revokeArgs := &api.RevokeCertArgs{
		CertificateIds: []int{certificateIdInt}, // Certificate ID expects array of integers
		Reason:         5,                       // reason = 5 means Cessation of Operation
		Comment:        "Terraform destroy called on provider with associated cert ID",
	}

	err := kfClient.RevokeCert(revokeArgs)
	if err != nil {
		response.Diagnostics.AddError("Certificate revocation error.", fmt.Sprintf("Could not revoke cert '%s' on Keyfactor: "+err.Error(), certificateId))
	}

	// Remove resource from state
	response.State.RemoveResource(ctx)

}

func (r resourceKeyfactorCertificate) ImportState(ctx context.Context, request tfsdk.ImportResourceStateRequest, response *tfsdk.ImportResourceStateResponse) {
	var state KeyfactorCertificate
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate resource")
	certificateId := request.ID
	certificateIdInt, err := strconv.Atoi(certificateId)
	if err != nil {
		response.Diagnostics.AddError("Import error.", fmt.Sprintf("Could not convert cert ID '%s' to integer: "+err.Error(), certificateId))
		return
	}

	tflog.SetField(ctx, "certificate_id", certificateId)

	// Get certificate context
	args := &api.GetCertificateContextArgs{
		IncludeMetadata:  boolToPointer(true),
		IncludeLocations: boolToPointer(true),
		CollectionId:     nil,
		Id:               certificateIdInt,
	}
	certificateData, err := r.p.client.GetCertificateContext(args)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+err.Error(), certificateId),
		)
		return
	}

	// Get the password out of current schema
	password := ""
	csr := ""

	// Download and assign certificates to proper location
	leaf, chain, priv, dErr := downloadCertificate(certificateData.Id, r.p.client, password, csr != "")
	if dErr != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErr.Error(), certificateId),
		)
		return
	}

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
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
