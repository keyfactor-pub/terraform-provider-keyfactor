package keyfactor

import (
	"context"
	"crypto/ecdsa"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
				Type:          types.StringType,
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Sensitive:     true,
				Description:   "Optional, used to read the private key if it is password protected.",
			},
			"subject": {
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "KeyfactorCertificate subject",
				Attributes: tfsdk.SingleNestedAttributes(map[string]tfsdk.Attribute{
					"subject_common_name": {
						Type:          types.StringType,
						Computed:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject common name for new certificate",
					},
					"subject_locality": {
						Type:          types.StringType,
						Computed:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject locality for new certificate",
					},
					"subject_organization": {
						Type:          types.StringType,
						Computed:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject organization for new certificate",
					},
					"subject_state": {
						Type:          types.StringType,
						Computed:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject state for new certificate",
					},
					"subject_country": {
						Type:          types.StringType,
						Computed:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject country for new certificate",
					},
					"subject_organizational_unit": {
						Type:          types.StringType,
						Computed:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject organizational unit for new certificate",
					},
				}),
			},
			"certificate_authority": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				//DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
				//	return strings.EqualFold(old, new)
				//},
				Description: "Name of certificate authority to deploy certificate with Ex: Example Company CA 1",
			},
			"certificate_template": {
				Type:          types.StringType,
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "Short name of certificate template to be deployed",
			},
			"dns_sans": {
				Type:          types.ListType{ElemType: types.StringType},
				Computed:      true,
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
				Computed:      true,
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
				Computed:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "List of IPs to use as subjects of the certificate",
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
			"id": {
				Type:        types.Int64Type,
				Required:    true,
				Description: "Keyfactor certificate identifier.",
			},
			"collection_id": {
				Type:        types.Int64Type,
				Required:    false,
				Optional:    true,
				Description: "Optional certificate collection identifier used to ensure user access to the certificate.",
			},
			"keyfactor_request_id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Keyfactor request ID necessary for deploying certificate",
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
	certificateID := state.ID.Value
	certificateIDInt := int(certificateID)

	collectionID := state.CollectionId.Value
	collectionIdInt := int(collectionID)

	tflog.SetField(ctx, "collection_id", collectionID)
	tflog.SetField(ctx, "certificate_id", certificateID)

	// Get certificate context
	tflog.Info(ctx, fmt.Sprintf("Attempting to lookup certificate '%v' in Keyfactor.", certificateID))
	tflog.Debug(ctx, "Calling Keyfactor GO Client GetCertificateContext")
	args := &api.GetCertificateContextArgs{
		IncludeMetadata:  boolToPointer(true),
		IncludeLocations: boolToPointer(true),
		CollectionId:     intToPointer(collectionIdInt),
		Id:               certificateIDInt,
	}
	cResp, err := r.p.client.GetCertificateContext(args)
	if err != nil {
		tflog.Error(ctx, "Error calling Keyfactor Go Client GetCertificateContext")
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+err.Error(), certificateID),
		)
		return
	}

	// Get the password out of current schema
	csr := state.CSR.Value
	password := state.KeyPassword.Value

	if password == "" {
		tflog.Debug(ctx, "Generating password. This will be stored in the state file, but is only used to download and parse the PFX to PEM fields.")
		password = generatePassword(32, 1, 1, 1)
		state.KeyPassword.Value = password
	}

	var (
		leaf  string
		chain = ""
		pKey  = ""
		dErr  = error(nil)
	)

	if cResp.HasPrivateKey {
		tflog.Info(ctx, "Requested certificate has a private key attempting to recover from Keyfactor Command.")
		pKeyO, _, chainO, dErrO := r.p.client.RecoverCertificate(certificateIDInt, "", "", "", password)
		if dErrO != nil {
			response.Diagnostics.AddError(
				"Error reading Keyfactor certificate.",
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErrO.Error(), certificateID),
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
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+lbErr.Error(), certificateID),
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
				fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+lbErr.Error(), certificateID),
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

	if dErr != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErr.Error(), certificateID),
		)
	}

	subject := flattenSubject(cResp.IssuedDN)
	dnsSans, ipSans, uriSans := flattenSANs(cResp.SubjectAltNameElements)
	metadata := flattenMetadata(cResp.Metadata)

	var result = KeyfactorCertificate{
		ID:           types.Int64{Value: state.ID.Value},
		CSR:          types.String{Value: csr},
		Subject:      subject,
		DNSSANs:      dnsSans,
		IPSANs:       ipSans,
		URISANs:      uriSans,
		SerialNumber: types.String{Value: cResp.SerialNumber},
		IssuerDN: types.String{
			Value: cResp.IssuerDN,
		},
		Thumbprint:  types.String{Value: cResp.Thumbprint},
		PEM:         types.String{Value: leaf},
		PEMChain:    types.String{Value: chain},
		PrivateKey:  types.String{Value: pKey},
		KeyPassword: types.String{Value: state.KeyPassword.Value},
		CertificateAuthority: types.String{
			Value: cResp.CertificateAuthorityName,
		},
		CertificateTemplate: types.String{Value: cResp.TemplateName},
		RequestId:           types.Int64{Value: int64(cResp.CertRequestId)},
		Metadata:            metadata,
	}

	// Set state
	diags = response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}
