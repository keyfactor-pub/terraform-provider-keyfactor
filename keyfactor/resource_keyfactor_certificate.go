package keyfactor

import (
	"context"
	"crypto/ecdsa"
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Keyfactor/keyfactor-go-client/v2/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"log"
	"strconv"
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
			"subject": {
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
				Description:   "KeyfactorCertificate subject",
				Attributes: tfsdk.SingleNestedAttributes(map[string]tfsdk.Attribute{
					"subject_common_name": {
						Type:          types.StringType,
						Optional:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject common name for new certificate",
					},
					"subject_locality": {
						Type:          types.StringType,
						Optional:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject locality for new certificate",
					},
					"subject_organization": {
						Type:          types.StringType,
						Optional:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject organization for new certificate",
					},
					"subject_state": {
						Type:          types.StringType,
						Optional:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject state for new certificate",
					},
					"subject_country": {
						Type:          types.StringType,
						Optional:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject country for new certificate",
					},
					"subject_organizational_unit": {
						Type:          types.StringType,
						Optional:      true,
						PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
						Description:   "Subject organizational unit for new certificate",
					},
				}),
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
			"id": {
				Type:        types.Int64Type,
				Computed:    true,
				Description: "Keyfactor certificate ID",
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
	if (plan.CSR.IsNull() && plan.Subject.IsNull()) || (!plan.CSR.IsNull() && !plan.Subject.IsNull()) || (csr == "" && plan.Subject.IsNull()) {
		response.Diagnostics.AddError(
			"Invalid certificate resource definition.",
			"You must provide either a CSR or a Subject to create a certificate.",
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
	diags = plan.Metadata.ElementsAs(ctx, &metadata, true)

	sans := append(dnsSANs, ipSANs...)
	sans = append(sans, uriSANs...)

	if !plan.CSR.IsNull() && csr != "" {
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

		// Set state
		var result = KeyfactorCertificate{
			ID:                   types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorID)},
			CSR:                  types.String{Value: csr},
			Subject:              plan.Subject,
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
			CertificateTemplate:  plan.CertificateTemplate,
			RequestId:            types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorRequestID)},
			Metadata:             plan.Metadata,
			CollectionId:         plan.CollectionId,
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	} else {
		subject := make(map[string]interface{})
		subjectObj := plan.Subject.Attrs
		for k, v := range subjectObj {
			subject[k] = v.String()
		}
		PFXArgs := &api.EnrollPFXFctArgs{
			CustomFriendlyName:          "Terraform",
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
				SubjectCommonName:         subject["subject_common_name"].(string),
				SubjectLocality:           subject["subject_locality"].(string),
				SubjectOrganization:       subject["subject_organization"].(string),
				SubjectCountry:            subject["subject_country"].(string),
				SubjectOrganizationalUnit: subject["subject_organizational_unit"].(string),
				SubjectState:              subject["subject_state"].(string),
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
			ID:                   types.Int64{Value: int64(enrolledId)},
			CSR:                  plan.CSR,
			Subject:              plan.Subject,
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
			RequestId:            types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorRequestID)},
			Metadata:             plan.Metadata,
			CollectionId:         plan.CollectionId,
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

	tflog.Info(ctx, "Read called on certificate resource")
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
	_, err := r.p.client.GetCertificateContext(args)
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
	_, _, _, dErr := downloadCertificate(certificateIdInt, r.p.client, state.KeyPassword.Value, csr != "")
	if dErr != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErr.Error(), certificateId),
		)
	}

	//var result = KeyfactorCertificate{
	//	ID:           types.Int64{Value: state.ID.Value},
	//	CSR:          types.String{Value: csr},
	//	Subject:      state.Subject,
	//	DNSSANs:      state.DNSSANs,
	//	IPSANs:       state.IPSANs,
	//	URISANs:      state.URISANs,
	//	SerialNumber: state.SerialNumber,
	//	IssuerDN:     state.IssuerDN,
	//	Thumbprint:   state.Thumbprint,
	//	PEM:          types.String{Value: leaf},
	//	PEMChain:     types.String{Value: chain},
	//	PrivateKey:   types.String{Value: pKey},
	//	KeyPassword:  types.String{Value: password},
	//	//PEM:                  state.PEM,
	//	//PEMChain:             state.PEMChain,
	//	//PrivateKey:           state.PrivateKey,
	//	//KeyPassword:          state.KeyPassword,
	//	CertificateAuthority: state.CertificateAuthority,
	//	CertificateTemplate:  state.CertificateTemplate,
	//	RequestId:            state.RequestId,
	//	Metadata:             state.Metadata,
	//}

	// Set state
	diags = response.State.Set(ctx, &state)
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
					CertID:   int(state.ID.Value),
					Metadata: metaInterface,
				})
			if err != nil {
				response.Diagnostics.AddError("Certificate metadata update error.", fmt.Sprintf("Could not update cert '%s''s metadata on Keyfactor: "+err.Error(), state.ID.Value))
				return
			}

		}

		// Set state
		var result = KeyfactorCertificate{
			ID:                   types.Int64{Value: state.ID.Value},
			CSR:                  types.String{Value: csr},
			Subject:              state.Subject,
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
			RequestId:            state.RequestId,
			Metadata:             plan.Metadata,
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			return
		}
	} else {
		// Set state
		var result = KeyfactorCertificate{
			ID:                   types.Int64{Value: state.ID.Value},
			CSR:                  state.CSR,
			Subject:              state.Subject,
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
			RequestId:            state.RequestId,
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

	// Delete order by calling API
	log.Println("[INFO] Deleting certificate resource")

	// When Terraform Destroy is called, we want Keyfactor to revoke the certificate.

	tflog.Info(ctx, fmt.Sprintf("Revoking certificate %v in Keyfactor", certificateId))

	revokeArgs := &api.RevokeCertArgs{
		CertificateIds: []int{int(certificateId)}, // Certificate ID expects array of integers
		Reason:         5,                         // reason = 5 means Cessation of Operation
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
	priv, leaf, chain, dErr := downloadCertificate(certificateData.Id, r.p.client, password, csr != "")
	if dErr != nil {
		response.Diagnostics.AddError(
			"Error reading Keyfactor certificate.",
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor: "+dErr.Error(), certificateId),
		)
		return
	}

	var result = KeyfactorCertificate{
		ID:                   types.Int64{Value: state.ID.Value},
		CSR:                  types.String{Value: csr},
		Subject:              state.Subject,
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
		RequestId:            state.RequestId,
		Metadata:             state.Metadata,
	}

	// Set state
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func downloadCertificate(id int, kfClient *api.Client, password string, csrEnrollment bool) (string, string, string, error) {
	certificateContext, err := kfClient.GetCertificateContext(&api.GetCertificateContextArgs{Id: id})
	if err != nil {
		return "", "", "", err
	}

	template, err := kfClient.GetTemplate(certificateContext.TemplateId)
	if err != nil {
		return "", "", "", err
	}

	recoverable := false

	if template.KeyRetention != "None" {
		recoverable = true
	}

	var privPem []byte
	var leafPem []byte
	var chainPem []byte

	if !recoverable || csrEnrollment {

		leaf, chain, err := kfClient.DownloadCertificate(id, "", "", "")
		if err != nil {
			return "", "", "", err
		}

		// Encode DER to PEM
		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		for _, i := range chain {
			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})...)
		}

	} else {

		priv, leaf, chain, err := kfClient.RecoverCertificate(id, "", "", "", password)
		if err != nil {
			return "", "", "", err
		}
		if err != nil {
			return "", "", "", err
		}

		// Encode DER to PEM
		leafPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
		for _, i := range chain {
			chainPem = append(chainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.Raw})...)
		}

		// Figure out the format of the private key, then encode it to PEM
		rsa, ok := priv.(*rsa2.PrivateKey)
		if ok {
			buf := x509.MarshalPKCS1PrivateKey(rsa)
			if len(buf) > 0 {
				privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "RSA PRIVATE KEY"})
			}
		}

		ecc, ok := priv.(*ecdsa.PrivateKey)
		if ok {
			// We don't really care about the error here. An error just means that the key will be blank which isn't a
			// reason to fail
			buf, _ := x509.MarshalECPrivateKey(ecc)
			if len(buf) > 0 {
				privPem = pem.EncodeToMemory(&pem.Block{Bytes: buf, Type: "EC PRIVATE KEY"})
			}
		}
	}

	return string(leafPem), string(chainPem), string(privPem), nil
}
