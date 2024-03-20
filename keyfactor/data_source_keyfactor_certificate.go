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
	"strconv"
)

type dataSourceCertificateType struct{}

func (r dataSourceCertificateType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"csr": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Base-64 encoded certificate signing request (CSR)",
			},
			"key_password": {
				Type:     types.StringType,
				Optional: true,
				//PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Sensitive:   true,
				Description: "Password used to recover the private key from Keyfactor Command. NOTE: If no value is provided a random password will be generated for key recovery. This value is not stored and does not encrypt the private key in Terraform state.",
			},
			"common_name": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject common name (CN) of the certificate.",
			},
			"locality": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject locality (L) of the certificate",
			},
			"organization": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject organization (O) of the certificate",
			},
			"state": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject state (ST) of the certificate",
			},
			"country": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject country of the certificate",
			},
			"organizational_unit": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Subject organizational unit (OU) of the certificate",
			},
			"certificate_authority": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	return strings.EqualFold(old, new)
				//},
				Description: "Name of certificate authority (CA) to deploy certificate with Ex: Example Company CA 1",
			},
			"certificate_template": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Short name of certificate template to be used. Ex: Server Authentication",
			},
			"dns_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "List of DNS subject alternative names (DNS SANs) of the certificate. Ex: www.example.com",
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
			},
			"uri_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "List of URI subject alternative names (URI SANs) of the certificate. Ex: https://www.example.com",
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	// For some reason Terraform detects this particular function as having drift; this function
				//	// gives us a definitive answer.
				//	return !d.HasChange(k)
				//},
			},
			"ip_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "List of IP subject alternative names (IP SANs) of the certificate. Ex: 192.168.0.200",
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
				Required: true,
				Description: "Keyfactor certificate identifier. This can be any of the following values: thumbprint, CN, " +
					"or Keyfactor Command Certificate ID. If using CN to lookup the last issued certificate, the CN must " +
					"be an exact match and if multiple certificates are returned the certificate that was most recently " +
					"issued will be returned. ",
			},
			"collection_id": {
				Type:        types.Int64Type,
				Required:    false,
				Optional:    true,
				Description: "Optional certificate collection identifier used to ensure user access to the certificate.",
			},
			"command_request_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Keyfactor Command request ID.",
			},
			"certificate_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Keyfactor Command certificate ID.",
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
		},
	}, nil
}

func (r dataSourceCertificateType) NewDataSource(ctx context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceCertificate{
		p: *(p.(*provider)),
	}, nil
}

type dataSourceCertificate struct {
	p provider
}

func (r dataSourceCertificate) Read(ctx context.Context, request tfsdk.ReadDataSourceRequest, response *tfsdk.ReadDataSourceResponse) {
	var state KeyfactorCertificate

	tflog.Info(ctx, "Reading terraform data resource 'certificate'.")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	// determine if certificateID is an int or string
	// if int, then it is a Keyfactor Command Certificate ID
	// if string, then it is a certificate thumbprint or CN
	certificateIDInt, cIdErr := strconv.Atoi(state.ID.Value)
	if cIdErr != nil {
		certificateIDInt = -1
	}
	var (
		certificateCN         string
		certificateThumbprint string
	)
	// Check if certificateID is a thumbprint or CN
	if certificateIDInt == -1 {
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
	tflog.SetField(ctx, "certificate_id", certificateIDInt)
	tflog.SetField(ctx, "certificate_cn", certificateCN)
	tflog.SetField(ctx, "certificate_thumbprint", certificateThumbprint)

	// Get certificate context
	tflog.Info(ctx, fmt.Sprintf("Attempting to lookup certificate '%v' in Keyfactor.", state.ID.Value))
	tflog.Debug(ctx, "Calling Keyfactor GO Client GetCertificateContext")
	args := &api.GetCertificateContextArgs{
		IncludeMetadata:      boolToPointer(true),
		IncludeLocations:     boolToPointer(true),
		IncludeHasPrivateKey: boolToPointer(true),
		CollectionId:         intToPointer(collectionIdInt),
		Id:                   certificateIDInt,
		CommonName:           certificateCN,
		Thumbprint:           certificateThumbprint,
	}
	cResp, err := r.p.client.GetCertificateContext(args)
	if err != nil {
		tflog.Error(ctx, "Error calling Keyfactor Go Client GetCertificateContext")
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+err.Error(), state.ID.Value),
		)
		return
	}

	// Get the password out of current schema
	csr := state.CSR.Value
	password := state.KeyPassword.Value

	//if password == "" {
	//	tflog.Debug(ctx, "Generating password. This will be stored in the state file, but is only used to download and parse the PFX to PEM fields.")
	//	password = generatePassword(32, 1, 1, 1)
	//	state.KeyPassword.Value = password
	//}

	var (
		leaf  string
		chain = ""
		pKey  = ""
		dErr  = error(nil)
	)

	if cResp.HasPrivateKey {
		if password == "" {
			password = generatePassword(32, 4, 4, 4)
		}
		tflog.Info(ctx, "Requested certificate has a private key attempting to recover from Keyfactor Command.")
		pKeyO, _, chainO, dErrO := r.p.client.RecoverCertificate(cResp.Id, "", "", "", password, collectionIdInt)
		if dErrO != nil {
			tflog.Error(ctx, fmt.Sprintf("Unable to recover private key for certificate '%v' from Keyfactor Command.", cResp.Id))
			response.Diagnostics.AddWarning(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+dErrO.Error(), cResp.Id),
			)
		}
		// Convert string to []byte and then to pem.
		//leaf = string(pem.EncodeToMemory(&pem.Block{
		//	Type:  "CERTIFICATE",
		//	Bytes: leafO.Raw,
		//}))
		lBytes, lbErr := base64.StdEncoding.DecodeString(cResp.ContentBytes)
		if lbErr != nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+lbErr.Error(), state.ID.Value),
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
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+lbErr.Error(), state.ID.Value),
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

		//attempt to get chain from Keyfactor Command via certificate ID and download
		tflog.Debug(ctx, "Attempting to download certificate chain from Keyfactor Command.")
		_, dChain, dChainErr := r.p.client.DownloadCertificate(cResp.Id, "", "", "")
		if dChainErr != nil {
			tflog.Error(ctx, "Error downloading certificate chain from Keyfactor Command.")
			response.Diagnostics.AddWarning(
				"Certificate Download Error",
				fmt.Sprintf("Could not dowload certificate '%s' from Keyfactor. Chain will not be included: %s", state.ID.Value, dChainErr.Error()),
			)
		}
		if dChain != nil {
			tflog.Debug(ctx, "Recovered certificate chain from Keyfactor Command:")
			for _, cert := range dChain {
				chainLink := string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				}))

				//check if chain is equal to leaf and if it is, skip it
				if chainLink == leaf {
					tflog.Debug(ctx, "Skipping leaf certificate in chain.")
					continue
				}

				chain = chain + chainLink
				tflog.Debug(ctx, chainLink)
			}
		} else {
			tflog.Debug(ctx, "No certificate chain recovered from Keyfactor Command.")
		}
	}

	if dErr != nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command: "+dErr.Error(), state.ID.Value),
		)
	}

	cn, ou, o, l, st, c := expandSubject(cResp.IssuedDN)
	dnsSans, ipSans, uriSans := flattenSANs(cResp.SubjectAltNameElements, state.DNSSANs, state.IPSANs, state.URISANs)
	metadata := flattenMetadata(cResp.Metadata)

	var result = KeyfactorCertificate{
		ID:                 types.String{Value: state.ID.Value},
		CSR:                types.String{Value: csr},
		CommonName:         cn,
		Country:            c,
		Locality:           l,
		Organization:       o,
		OrganizationalUnit: ou,
		State:              st,
		DNSSANs:            dnsSans,
		IPSANs:             ipSans,
		URISANs:            uriSans,
		SerialNumber:       types.String{Value: cResp.SerialNumber},
		IssuerDN: types.String{
			Value: cResp.IssuerDN,
		},
		Thumbprint:  types.String{Value: cResp.Thumbprint},
		PEM:         types.String{Value: leaf},
		PEMCACert:   types.String{Value: chain},
		PEMChain:    types.String{Value: fmt.Sprintf("%s%s", leaf, chain)},
		PrivateKey:  types.String{Value: pKey},
		KeyPassword: types.String{Value: state.KeyPassword.Value},
		CertificateAuthority: types.String{
			Value: cResp.CertificateAuthorityName,
		},
		CertificateTemplate: types.String{Value: cResp.TemplateName},
		RequestId:           types.Int64{Value: int64(cResp.CertRequestId)},
		CertificateId:       types.Int64{Value: int64(cResp.Id)},
		Metadata:            metadata,
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
