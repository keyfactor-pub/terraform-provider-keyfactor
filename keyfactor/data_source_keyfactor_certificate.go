package keyfactor

import (
	"context"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"strings"
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
				Description:   "Password to protect certificate and private key with",
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
			"keyfactor_id": {
				Type:        types.Int64Type,
				Required:    true,
				Description: "Keyfactor certificate ID",
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

	tflog.Info(ctx, "Read called on certificate resource")
	diags := request.Config.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
	certificateId := state.ID.Value
	certificateIdInt := int(certificateId)

	tflog.SetField(ctx, "certificate_id", certificateId)

	// Get certificate context
	args := &api.GetCertificateContextArgs{
		IncludeMetadata:  boolToPointer(true),
		IncludeLocations: boolToPointer(true),
		CollectionId:     nil,
		Id:               certificateIdInt,
	}
	cResp, err := r.p.client.GetCertificateContext(args)
	if err != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+err.Error(), certificateId),
		)
		return
	}

	// Get the password out of current schema
	csr := state.CSR.Value

	// Download and assign certificates to proper location
	//leaf, chain, pKey, dErr := downloadCertificate(certificateIdInt, r.p.client, state.KeyPassword.Value, csr != "")
	leaf, chain, pKey, dErr := downloadCertificate(certificateIdInt, r.p.client, state.KeyPassword.Value, csr != "")
	if dErr != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErr.Error(), certificateId),
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

func flattenSubject(subject string) types.Object {
	data := make(map[string]string) // Inner subject interface is a string mapped interface
	if subject != "" {
		subjectFields := strings.Split(subject, ",") // Separate subject fields into slices
		for _, field := range subjectFields {        // Iterate and assign slices to associated map
			if strings.Contains(field, "CN=") {
				//result["subject_common_name"] = types.String{Value: strings.Replace(field, "CN=", "", 1)}
				data["subject_common_name"] = strings.Replace(field, "CN=", "", 1)
			} else if strings.Contains(field, "OU=") {
				//result["subject_organizational_unit"] = types.String{Value: strings.Replace(field, "OU=", "", 1)}
				data["subject_organizational_unit"] = strings.Replace(field, "OU=", "", 1)
			} else if strings.Contains(field, "C=") {
				//result["subject_country"] = types.String{Value: strings.Replace(field, "C=", "", 1)}
				data["subject_country"] = strings.Replace(field, "C=", "", 1)
			} else if strings.Contains(field, "L=") {
				//result["subject_locality"] = types.String{Value: strings.Replace(field, "L=", "", 1)}
				data["subject_locality"] = strings.Replace(field, "L=", "", 1)
			} else if strings.Contains(field, "ST=") {
				//result["subject_state"] = types.String{Value: strings.Replace(field, "ST=", "", 1)}
				data["subject_state"] = strings.Replace(field, "ST=", "", 1)
			} else if strings.Contains(field, "O=") {
				//result["subject_organization"] = types.String{Value: strings.Replace(field, "O=", "", 1)}
				data["subject_organization"] = strings.Replace(field, "O=", "", 1)
			}
		}

	}
	result := types.Object{
		Attrs: map[string]attr.Value{
			"subject_common_name":         types.String{Value: data["subject_common_name"]},
			"subject_locality":            types.String{Value: data["subject_locality"]},
			"subject_organization":        types.String{Value: data["subject_organization"]},
			"subject_state":               types.String{Value: data["subject_state"]},
			"subject_country":             types.String{Value: data["subject_country"]},
			"subject_organizational_unit": types.String{Value: data["subject_organizational_unit"]},
		},
		AttrTypes: map[string]attr.Type{
			"subject_common_name":         types.StringType,
			"subject_locality":            types.StringType,
			"subject_organization":        types.StringType,
			"subject_state":               types.StringType,
			"subject_country":             types.StringType,
			"subject_organizational_unit": types.StringType,
		},
	}

	return result
}

func flattenMetadata(metadata interface{}) types.Map {
	data := make(map[string]string)
	if metadata != nil {
		for k, v := range metadata.(map[string]interface{}) {
			data[k] = v.(string)
		}
	}

	result := types.Map{
		Elems:    map[string]attr.Value{},
		ElemType: types.StringType,
	}
	for k, v := range data {
		result.Elems[k] = types.String{Value: v}
	}
	return result
}

func flattenSANs(sans []api.SubjectAltNameElements) (types.List, types.List, types.List) {
	sanIP4Array := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	sanDNSArray := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	sanURIArray := types.List{
		ElemType: types.StringType,
		Elems:    []attr.Value{},
	}
	if len(sans) > 0 {
		for _, san := range sans {
			sanName := mapSanIDToName(san.Type)
			if sanName == "IP Address" {
				sanIP4Array.Elems = append(sanIP4Array.Elems, types.String{Value: san.Value})
			} else if sanName == "DNS Name" {
				sanDNSArray.Elems = append(sanDNSArray.Elems, types.String{Value: san.Value})
			} else if sanName == "Uniform Resource Identifier" {
				sanURIArray.Elems = append(sanURIArray.Elems, types.String{Value: san.Value})
			}
		}
	}

	return sanDNSArray, sanIP4Array, sanURIArray
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
