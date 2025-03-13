package keyfactor

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type resourceCommandCertificateType struct{}

func (r resourceCommandCertificateType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
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
			"use_cn_as_friendly_name": {
				Type:     types.BoolType,
				Computed: false,
				Description: "Only applicable for PFX enrollments. Use the common name as the friendly name for the" +
					" certificate. Defaults to `true`. " +
					"NOTE: Keyfactor Command must be configured to `allow custom friendly name` for this to work" +
					" under `Application Settings > Enrollment > PFX`.",
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"friendly_name": {
				Type:     types.StringType,
				Computed: false,
				Description: "Only applicable for PFX enrollments. A friendly name for the certificate. " +
					"If not provided, " +
					"the common name will be used unless `use_cn_as_friendly_name` is set to `false`.",
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"is_expired": {
				Type:          types.BoolType,
				Computed:      true,
				Description:   "Whether the certificate is expired",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"is_revoked": {
				Type:          types.BoolType,
				Computed:      true,
				Description:   "Whether the certificate is revoked",
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"is_pending_revocation": {
				Type:        types.BoolType,
				Computed:    true,
				Description: "Whether the certificate is pending revocation",
			},
			"expiry_warn_days": {
				Type:     types.Int64Type,
				Optional: true,
				Description: fmt.Sprintf(
					"Number of days before expiry to warn about the certificate. "+
						"Defaults to %d days.", DEFAULT_EXPIRY_WARNING_DAYS,
				),
			},
			"renewal_config": {
				Attributes: tfsdk.SingleNestedAttributes(
					map[string]tfsdk.Attribute{
						"force_renewal": {
							Type:        types.BoolType,
							Description: "Will force certificate to be renewed",
							Optional:    true,
							PlanModifiers: []tfsdk.AttributePlanModifier{
								tfsdk.RequiresReplaceIf(
									// The conditional function
									forceIfTrue,
									"Triggers resource replacement when 'force_renewal' is set to 'true'.", // Description
									"Triggers resource replacement when `force_renewal` is set to `true`.", // Markdown Description
								),
							},
						},
						"renew_days": {
							Type:        types.Int64Type,
							Required:    true,
							Description: "The number of days before the certificate expires to renew.",
						},
						"renew_eligible": {
							Type:          types.BoolType,
							Computed:      true,
							PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
							Description:   "Whether the certificate is eligible for renewal.",
						},
						"revoke_on_renew": {
							Type:        types.BoolType,
							Optional:    true,
							Description: "Whether the existing certificate should be revoked on renewal.",
						},
					},
				),
				Optional:    true,
				Computed:    false,
				Description: "Configuration for certificate auto renewal. Includes whether auto-renewal is enabled and the number of days before expiry.",
			},
		},
		Description: "Manages a certificate in Keyfactor Command using the `/Enrollment` and `/Certificates` APIs",
	}, nil
}

func (r resourceCommandCertificateType) NewResource(_ context.Context, p tfsdk.Provider) (
	tfsdk.Resource,
	diag.Diagnostics,
) {
	return resourceCommandCertificate{
		p: *(p.(*provider)),
	}, nil
}

type resourceCommandCertificate struct {
	p provider
}

func (r resourceCommandCertificate) Create(
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
	var plan CommandCertificate
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

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
	if !plan.CSR.IsNull() && csr != "" { //Enroll CSR
		tflog.Debug(ctx, "Calling enrollCSR()")
		result, csrErr := r.enrollCSR(ctx, csr, &plan)
		if csrErr != nil {
			response.Diagnostics.Append(csrErr...)
			return
		}

		tflog.Debug(ctx, "Setting state")
		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}

		return
	} else { //Enroll PFX
		tflog.Debug(ctx, "Calling enrollPFXV2()")
		result, pfxErr := r.enrollPFXV2(ctx, &plan)
		if pfxErr.HasError() {
			response.Diagnostics.Append(pfxErr...)
			return
		}

		if result == nil {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				"empty response returned from Keyfactor Command after PFX enrollment",
			)
			return
		}

		tflog.Debug(ctx, "Setting state")
		diags = response.State.Set(ctx, *result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}
	}

}

func (r resourceCommandCertificate) Read(
	ctx context.Context,
	request tfsdk.ReadResourceRequest,
	response *tfsdk.ReadResourceResponse,
) {
	var state CommandCertificate
	tflog.Info(ctx, "Read called on CommandCertificate resource")
	if response == nil {
		tflog.Warn(ctx, "nil ReadResourceResponse")
	}

	tflog.Debug(ctx, "Reading state file")
	diags := request.State.Get(ctx, &state)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading state file")
		return
	}

	// Determine certificate ID type and resolve CN or thumbprint
	certificateID, idTypeErr := strconv.Atoi(state.ID.Value)
	if idTypeErr != nil {
		certificateID = UNKNOWN_CERTIFICATE_ID
	}
	collectionIdInt := int(state.CollectionId.Value)

	thumbprint, commonName := determineCertificateIdType(state.ID.Value)
	logInitialCertificateFields(ctx, certificateID, commonName, thumbprint, collectionIdInt)

	// Prepare args for API call
	apiArgs := prepareCertificateContextArgs(certificateID, collectionIdInt, thumbprint, commonName)

	// Fetch certificate context
	certGetResp, apiErr := r.p.client.GetCertificateContext(apiArgs)
	if hasAPIErrors(ctx, apiErr, state.ID.Value, &response.Diagnostics) {
		tflog.Warn(ctx, fmt.Sprintf("Failed to retrieve certificate from GET /Certificates/%d", certificateID))
	}

	// Attempt to recover or download certificate from Command
	leafPEM, chainPEM, pKeyPEM, rDiags := recoverOrDownloadCertificate(
		ctx,
		certificateID,
		collectionIdInt,
		state.KeyPassword.Value,
		r.p.client,
	)

	// Handle leaf PEM encoding for certificates without private keys
	if certGetResp != nil && leafPEM == "" {
		leafPEM, _ = encodeCertificate(ctx, certGetResp.ContentBytes, certificateID)
	}

	if leafPEM == "" {
		response.Diagnostics.Append(rDiags...)
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Failed to retrieve certificate '%s' from Keyfactor Command. "+
					"Please check the certificate ID and try again.", state.ID.Value,
			),
		)
		return
	}

	leaf, lDiags := parseLeafCert(
		ctx,
		leafPEM,
	)
	response.Diagnostics.Append(lDiags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error parsing certificate")
		return
	} else if leaf == nil {
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Failed to parse certificate '%s' from Keyfactor Command. "+
					"Please check the certificate ID and try again.", state.ID.Value,
			),
		)
		return
	}

	sn := leaf.SerialNumber.String()
	issuerDN := leaf.Issuer.String()
	tp, _ := GetCertificateThumbprint(leaf)
	fullChain := chainPEM
	if !strings.Contains(fullChain, leafPEM) {
		fullChain = leafPEM + chainPEM
	}

	caName := state.CertificateAuthority.Value
	templateName := state.CertificateTemplate.Value
	metadata := state.Metadata

	cn, l, s, c, o, ou := parseSubjectToTfState(*leaf)
	var warningDays int
	if state.ExpiryWarningDays.Null || state.ExpiryWarningDays.Unknown || state.ExpiryWarningDays.Value <= 0 {
		warningDays = DEFAULT_EXPIRY_WARNING_DAYS
	} else {
		warningDays = int(state.ExpiryWarningDays.Value)
	}

	var (
		revoked bool
		expired bool
		//expiring bool
		cDiags diag.Diagnostics
	)
	tflog.Debug(ctx, "Calling checkCertDiags()")
	revoked, _, expired, cDiags = checkCertDiags(ctx, certGetResp, warningDays, leaf)
	response.Diagnostics.Append(cDiags...)
	if certGetResp != nil {
		caName = certGetResp.CertificateAuthorityName
		certificateID = certGetResp.Id
		//templateName = certGetResp.TemplateName
		metadata = flattenMetadata(certGetResp.Metadata)
	}

	renewalConfig := state.RenewalConfig
	if state.RenewalConfig != nil {
		renewalConfig = &CertificateAutoRenewConfig{
			ForceRenewal: state.RenewalConfig.ForceRenewal,
			RenewDays:    state.RenewalConfig.RenewDays,
			//RenewEligible: types.Bool{
			//	Value: renewEligible,
			//},
			RevokeOnRenew: state.RenewalConfig.RevokeOnRenew,
		}
		if state.RenewalConfig.RenewDays.Value != 0 {
			ctx = tflog.SetField(ctx, "renew_days", state.RenewalConfig.RenewDays.Value)
			tflog.Info(ctx, "Checking if certificate is eligible for renewal.")
			renewDays := int(state.RenewalConfig.RenewDays.Value)
			renewEligible, _, _ := isExpiring(ctx, leaf, renewDays)
			if renewEligible {
				renewalConfig.RenewEligible = types.Bool{
					Unknown: false,
					Null:    false,
					Value:   renewEligible,
				}
			}
		}
	}

	tflog.Debug(ctx, "Creating state object for certificate.")
	result := CommandCertificate{
		ID:                 state.ID,
		CSR:                state.CSR,
		CommonName:         cn,
		Locality:           l,
		State:              s,
		Country:            c,
		Organization:       o,
		OrganizationalUnit: ou,
		DNSSANs:            DNSSANStoTerraform(leaf.DNSNames, false),
		IPSANs:             IPSANStoTerraform(leaf.IPAddresses, false),
		URISANs:            URISANStoTerraform(leaf.URIs, false),
		SerialNumber:       types.String{Value: sn, Null: isNullString(sn)},
		IssuerDN:           types.String{Value: issuerDN, Null: isNullString(issuerDN)},
		Thumbprint:         types.String{Value: tp, Null: isNullString(tp)},
		PEM:                types.String{Value: leafPEM, Null: isNullString(leafPEM)},
		PEMCACert:          types.String{Value: chainPEM, Null: isNullString(chainPEM)},
		PEMChain:           types.String{Value: fullChain, Null: isNullString(fullChain)},
		PrivateKey:         types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)},
		KeyPassword:        state.KeyPassword,
		CertificateAuthority: types.String{
			Value: caName,
			Null:  isNullString(caName),
		},
		CertificateTemplate: types.String{Value: templateName, Null: isNullString(templateName)},
		Metadata:            metadata,
		CertificateId:       types.Int64{Value: int64(certificateID), Null: isNullId(certificateID)},
		CollectionId:        state.CollectionId,
		FriendlyName:        state.FriendlyName,
		UseCNAsFriendlyName: state.UseCNAsFriendlyName,
		ExpiryWarningDays:   state.ExpiryWarningDays,
		IsExpired: types.Bool{
			Value: expired,
		},
		IsRevoked: types.Bool{
			Value: revoked,
		},
		IsPendingRevocation: types.Bool{
			Null: true,
		},
		RenewalConfig: renewalConfig,
	}

	// Set state
	tflog.Debug(ctx, "Setting state")
	sDiags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(sDiags...)
	if response.Diagnostics.HasError() {
		return
	}
}

func (r resourceCommandCertificate) Update(
	ctx context.Context,
	request tfsdk.UpdateResourceRequest,
	response *tfsdk.UpdateResourceResponse,
) {
	tflog.Info(ctx, "Update called on certificate resource")
	// Get plan values
	var plan CommandCertificate
	tflog.Debug(ctx, "Reading plan file")
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		tflog.Error(ctx, "Error reading plan file")
		return
	}

	// Get current state
	var state CommandCertificate
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

	collectionIdInt := int(state.CollectionId.Value)

	thumbprint, commonName := determineCertificateIdType(state.ID.Value)
	certificateID := int(state.CertificateId.Value)
	logInitialCertificateFields(ctx, certificateID, commonName, thumbprint, collectionIdInt)

	// Prepare args for API call
	apiArgs := prepareCertificateContextArgs(certificateID, collectionIdInt, thumbprint, commonName)

	var (
		revoked bool
		expired bool
		//expiring bool
		cDiags diag.Diagnostics
	)

	var warningDays int
	if plan.ExpiryWarningDays.Null || plan.ExpiryWarningDays.Unknown || plan.ExpiryWarningDays.Value <= 0 {
		warningDays = DEFAULT_EXPIRY_WARNING_DAYS
	} else {
		warningDays = int(plan.ExpiryWarningDays.Value)
	}

	// Fetch certificate context
	certGetResp, apiErr := r.p.client.GetCertificateContext(apiArgs)
	if hasAPIErrors(ctx, apiErr, state.ID.Value, &response.Diagnostics) {
		tflog.Warn(ctx, fmt.Sprintf("Failed to retrieve certificate from GET /Certificates/%d", certificateID))
	}

	leaf, lDiags := parseLeafCert(
		ctx,
		state.PEM.Value,
	)
	if lDiags.HasError() {
		//this should never happen unless state has been manually manipulated
		response.Diagnostics.Append(lDiags...)
		return
	}

	tflog.Debug(ctx, "Calling checkCertDiags()")
	revoked, _, expired, cDiags = checkCertDiags(ctx, certGetResp, warningDays, leaf)
	response.Diagnostics.Append(cDiags...)
	//if certGetResp != nil {
	//	caName = certGetResp.CertificateAuthorityName
	//	certificateID = certGetResp.Id
	//	//templateName = certGetResp.TemplateName
	//	metadata = flattenMetadata(certGetResp.Metadata)
	//}

	renewalConfig := state.RenewalConfig
	if plan.RenewalConfig != nil {
		renewalConfig = &CertificateAutoRenewConfig{
			ForceRenewal: plan.RenewalConfig.ForceRenewal,
			RenewDays:    plan.RenewalConfig.RenewDays,
			//RenewEligible: types.Bool{
			//	Value: renewEligible,
			//},
			RevokeOnRenew: plan.RenewalConfig.RevokeOnRenew,
		}
		if plan.RenewalConfig.RenewDays.Value != 0 {
			ctx = tflog.SetField(ctx, "renew_days", plan.RenewalConfig.RenewDays.Value)
			tflog.Info(ctx, "Checking if certificate is eligible for renewal.")
			renewDays := int(plan.RenewalConfig.RenewDays.Value)
			renewEligible, _, _ := isExpiring(ctx, leaf, renewDays)
			if renewEligible {
				renewalConfig.RenewEligible = types.Bool{
					Unknown: false,
					Null:    false,
					Value:   renewEligible,
				}
			}
		}
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
				},
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
		var result = CommandCertificate{
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
			PEMCACert:            plan.PEMChain,
			PEMChain:             types.String{Value: fmt.Sprintf("%s%s", plan.PEM.Value, plan.PEMChain.Value)},
			PrivateKey:           plan.PrivateKey,
			KeyPassword:          plan.KeyPassword,
			CertificateAuthority: plan.CertificateAuthority,
			CertificateTemplate:  plan.CertificateTemplate,
			Metadata:             plan.Metadata,
			UseCNAsFriendlyName:  state.UseCNAsFriendlyName,
			FriendlyName:         state.FriendlyName,
			CollectionId:         state.CollectionId,
			ExpiryWarningDays:    plan.ExpiryWarningDays,
			IsExpired: types.Bool{
				Value: expired,
			},
			IsRevoked: types.Bool{
				Value: revoked,
			},
			IsPendingRevocation: types.Bool{
				Null: true,
			},
			RenewalConfig: renewalConfig,
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
			tflog.Info(
				ctx,
				fmt.Sprintf("Updating metadata for certificate '%s' on Keyfactor Command.", state.ID.Value),
			)
			err := r.p.client.UpdateMetadata(
				&api.UpdateMetadataArgs{
					CertID:   int(state.CertificateId.Value),
					Metadata: planMetadataInterface,
				},
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
		tflog.Debug(ctx, "Creating CommandCertificate state object")
		var result = CommandCertificate{
			ID:                   state.ID,
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
			PEMCACert:            state.PEMCACert,
			PEMChain:             state.PEMChain,
			PrivateKey:           state.PrivateKey,
			KeyPassword:          plan.KeyPassword,
			CertificateId:        state.CertificateId,
			CertificateAuthority: state.CertificateAuthority,
			CertificateTemplate:  state.CertificateTemplate,
			Metadata:             plan.Metadata,
			UseCNAsFriendlyName:  state.UseCNAsFriendlyName,
			FriendlyName:         state.FriendlyName,
			CollectionId:         state.CollectionId,
			ExpiryWarningDays:    plan.ExpiryWarningDays,
			IsExpired: types.Bool{
				Value: expired,
			},
			IsRevoked: types.Bool{
				Value: revoked,
			},
			IsPendingRevocation: types.Bool{
				Null: true,
			},
			RenewalConfig: renewalConfig,
		}

		diags = response.State.Set(ctx, result)
		response.Diagnostics.Append(diags...)
		if response.Diagnostics.HasError() {
			tflog.Error(ctx, "Error setting state")
			return
		}
	}
}

func (r resourceCommandCertificate) Delete(
	ctx context.Context,
	request tfsdk.DeleteResourceRequest,
	response *tfsdk.DeleteResourceResponse,
) {
	tflog.Info(ctx, "Delete called on certificate resource")
	var state CommandCertificate
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

	if state.RenewalConfig != nil && !state.RenewalConfig.RevokeOnRenew.Value {
		// Remove resource from state without revocation
		tflog.Debug(ctx, "RevokeOnRenew is false, skipping revocation for certificate.")
		response.State.RemoveResource(ctx)
		tflog.Info(ctx, fmt.Sprintf("Certificate '%s' removed from state.", certificateId))
		return
	}

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

		if strings.Contains(err.Error(), "has previously been revoked") { // EJBCA specific?
			response.Diagnostics.AddWarning(
				"Certificate previously revoked",
				fmt.Sprintf(err.Error()),
			)
		} else {
			tflog.Error(ctx, fmt.Sprintf("Error revoking certificate '%d' on Keyfactor Command", certificateIdInt))
			response.Diagnostics.AddError(
				"Certificate revocation error.",
				fmt.Sprintf("Keyfactor Command could not revoke cert '%s' : "+err.Error(), state.ID.Value),
			)
			return
		}
	}

	// Remove resource from state
	tflog.Debug(ctx, "Removing certificate from state")
	response.State.RemoveResource(ctx)
	tflog.Info(ctx, fmt.Sprintf("Certificate '%s' removed from state.", certificateId))
}

func (r resourceCommandCertificate) ImportState(
	ctx context.Context,
	request tfsdk.ImportResourceStateRequest,
	response *tfsdk.ImportResourceStateResponse,
) {
	tflog.Info(ctx, "ImportState called on certificate resource")
	var state CommandCertificate
	if response.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Read called on certificate resource")
	certificateId := request.ID
	ctx = tflog.SetField(ctx, "certificate_id", certificateId)

	certificateIdInt, _ := strconv.Atoi(certificateId)

	// Prepare args for API call
	// Use of collection_id to import is not currently supported
	apiArgs := prepareCertificateContextArgs(certificateIdInt, 0, request.ID, request.ID)

	// Fetch certificate context
	certGetResp, apiErr := r.p.client.GetCertificateContext(apiArgs)
	if hasAPIErrors(ctx, apiErr, state.ID.Value, &response.Diagnostics) {
		tflog.Warn(ctx, fmt.Sprintf("Failed to retrieve certificate from GET /Certificates/%s", state.ID.Value))
	}

	tflog.Info(ctx, fmt.Sprintf("Attempting to retrieve certificate '%s' from Keyfactor Command.", state.ID.Value))
	tflog.Debug(ctx, "Calling recoverOrDownloadCertificate")
	leafPEM, chainPEM, pKeyPEM, rDiags := recoverOrDownloadCertificate(
		ctx,
		certificateIdInt,
		int(state.CollectionId.Value),
		state.KeyPassword.Value,
		r.p.client,
	)

	if rDiags.HasError() {
		tflog.Error(ctx, fmt.Sprintf("Error retrieving certificate '%s' from Keyfactor Command.", certificateId))
		response.Diagnostics.Append(rDiags...)
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf("Could not retrieve certificate '%s' from Keyfactor Command", certificateId),
		)
		return
	}

	// Handle leaf PEM encoding for certificates without private keys
	if certGetResp != nil && leafPEM == "" {
		leafPEM, _ = encodeCertificate(ctx, certGetResp.ContentBytes, certGetResp.Id)
	}

	if leafPEM == "" {
		response.Diagnostics.Append(rDiags...)
		response.Diagnostics.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
			fmt.Sprintf(
				"Failed to retrieve certificate '%s' from Keyfactor Command. "+
					"Please check the certificate ID and try again.", state.ID.Value,
			),
		)
		return
	}

	leaf := x509.Certificate{
		Raw: []byte(leafPEM),
	}
	sn := leaf.SerialNumber.String()
	issuerDN := leaf.Issuer.String()
	tp, _ := GetCertificateThumbprint(&leaf)
	fullChain := chainPEM
	if !strings.Contains(fullChain, leafPEM) {
		fullChain = leafPEM + chainPEM
	}

	caName := state.CertificateAuthority.Value
	templateName := state.CertificateTemplate.Value
	metadata := state.Metadata
	if certGetResp != nil {
		// Info that can only be retrieved with `Read Certificates` permissions
		caName = certGetResp.CertificateAuthorityName
		certificateIdInt = certGetResp.Id
		templateName = certGetResp.TemplateName
		metadata = flattenMetadata(certGetResp.Metadata)
		revoked := isRevoked(certGetResp)
		if revoked {
			response.Diagnostics.AddWarning(
				"Certificate revoked",
				fmt.Sprintf("Certificate '%s' is revoked", state.ID.Value),
			)
		}
	}

	cn, l, s, c, o, ou := parseSubjectToTfState(leaf)

	tflog.Debug(ctx, "Creating CommandCertificate object")
	var result = CommandCertificate{
		ID:                 state.ID,
		CSR:                state.CSR,
		CommonName:         cn,
		Locality:           l,
		State:              s,
		Country:            c,
		Organization:       o,
		OrganizationalUnit: ou,
		DNSSANs:            DNSSANStoTerraform(leaf.DNSNames, false),
		IPSANs:             IPSANStoTerraform(leaf.IPAddresses, false),
		URISANs:            URISANStoTerraform(leaf.URIs, false),
		SerialNumber:       types.String{Value: sn, Null: isNullString(sn)},
		IssuerDN:           types.String{Value: issuerDN, Null: isNullString(issuerDN)},
		Thumbprint:         types.String{Value: tp, Null: isNullString(tp)},
		PEM:                types.String{Value: leafPEM, Null: isNullString(leafPEM)},
		PEMCACert:          types.String{Value: chainPEM, Null: isNullString(chainPEM)},
		PEMChain:           types.String{Value: fullChain, Null: isNullString(fullChain)},
		PrivateKey:         types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)},
		KeyPassword:        state.KeyPassword,
		CertificateAuthority: types.String{
			Value: caName,
			Null:  isNullString(caName),
		},
		CertificateTemplate: types.String{Value: templateName, Null: isNullString(templateName)},
		Metadata:            metadata,
		CertificateId:       types.Int64{Value: int64(certificateIdInt), Null: isNullId(certificateIdInt)},
		CollectionId:        state.CollectionId,
		FriendlyName:        state.FriendlyName,
		UseCNAsFriendlyName: state.UseCNAsFriendlyName,
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

func (r resourceCommandCertificate) CertLookupByRequestID(
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

func (r resourceCommandCertificate) WaitForPendingCert(
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

func (r resourceCommandCertificate) HandlePendingCert(
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
				tflog.Debug(
					ctx,
					"Iterating through certificates pending internal validation from Keyfactor Command",
				)
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
				tflog.Debug(
					ctx,
					"Iterating through certificates pending external validation from Keyfactor Command",
				)
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

func (r resourceCommandCertificate) enrollPFXV2(ctx context.Context, plan *CommandCertificate) (
	*CommandCertificate,
	diag.Diagnostics,
) {

	var (
		autoPassword   string
		lookupPassword string
		pKeyPEM        string
		leafPEM        string
		chainPEM       string
	)

	collectionId := plan.CollectionId.Value
	collectionIdInt := int(collectionId)

	tflog.Info(ctx, "Resource is PFX certificate enrollment.")
	diags := diag.Diagnostics{}
	if plan.KeyPassword.Value == "" {
		tflog.Debug(ctx, "No password provided, generating random password.")

		autoPassword = generatePassword(
			PFXPasswordLength,
			PFXPasswordSpecialChars,
			PFXPasswordDigits,
			PFXPasswordUpperCases,
		)
		lookupPassword = autoPassword
	} else {
		tflog.Debug(ctx, "Password provided, using provided password.")
		lookupPassword = plan.KeyPassword.Value
	}

	useCNAsFriendlyName := true // Defaults to true for backwards compatability
	if !plan.UseCNAsFriendlyName.Null {
		useCNAsFriendlyName = plan.UseCNAsFriendlyName.Value
	}

	var friendlyName = plan.FriendlyName.Value
	if friendlyName == "" && useCNAsFriendlyName {
		friendlyName = plan.CommonName.Value
	}

	dnsSANs, ipSANs, uriSANs, dnsSANsDiags := r.parseSans(ctx, plan)
	if dnsSANsDiags.HasError() {
		diags.Append(dnsSANsDiags...)
	}

	metadata, metadataErr := r.parseMetadata(ctx, plan)
	if metadataErr != nil {
		diags.Append(metadataErr...)
	}

	tflog.Debug(ctx, "Creating API request.")
	PFXArgs := &api.EnrollPFXFctArgsV2{
		CustomFriendlyName:          friendlyName,
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
			SubjectLocality:           escapeCommas(plan.Locality.Value),
			SubjectOrganization:       escapeCommas(plan.Organization.Value),
			SubjectCountry:            escapeCommas(plan.Country.Value),
			SubjectOrganizationalUnit: escapeCommas(plan.OrganizationalUnit.Value),
			SubjectState:              escapeCommas(plan.State.Value),
		},
	}
	tflog.Debug(ctx, "API PFXArgs created.")

	//convert PFX args to JSON string
	tflog.Debug(ctx, "Converting PFXArgs to JSON.")
	jsonData, err := json.Marshal(PFXArgs)
	if err != nil {
		tflog.Error(ctx, "Error converting PFXArgs to JSON.")
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
			"Could not convert PFXArgs to JSON: "+err.Error(),
		)
		return nil, diags
	}
	ctx = tflog.SetField(ctx, "pfx_args", string(jsonData))

	tflog.Debug(ctx, fmt.Sprintf("PFXArgs: %s", string(jsonData)))
	tflog.Debug(ctx, fmt.Sprintf("Creating PFX certificate %s on Keyfactor.", PFXArgs.Subject.SubjectCommonName))
	tflog.Debug(ctx, "Calling EnrollPFXV2.")
	enrollResponse, err := r.p.client.EnrollPFXV2(PFXArgs)
	if err != nil {
		tflog.Error(ctx, "No response from Keyfactor Command after PFX enrollment.")
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
			fmt.Sprintf(
				"Could not create certificate %s on Keyfactor: "+err.Error(),
				PFXArgs.Subject.SubjectCommonName,
			),
		)
		return nil, diags
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
					diags.AddError(
						ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
						fmt.Sprintf(
							"Could not create certificate '%s' on Keyfactor Command: "+pErr.Error(),
							PFXArgs.Subject.SubjectCommonName,
						),
					)
					return nil, diags
				}
				approvedCert = waitResp
			} else {
				tflog.Error(
					ctx,
					fmt.Sprintf("Error handling pending certificate %s.", PFXArgs.Subject.SubjectCommonName),
				)
				diags.AddError(
					ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
					fmt.Sprintf(
						"Could not create certificate '%s' on Keyfactor Command: "+pErr.Error(),
						PFXArgs.Subject.SubjectCommonName,
					),
				)
				return nil, diags
			}
		}
		if approvedCert == nil {
			tflog.Error(
				ctx,
				fmt.Sprintf("Certificate '%s' is pending approval.", PFXArgs.Subject.SubjectCommonName),
			)
			diags.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
				fmt.Sprintf(
					"No response recieved on create certificate '%s' on Keyfactor Command: "+pErr.Error(),
					PFXArgs.Subject.SubjectCommonName,
				),
			)
			return nil, diags
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
	// Recover private key
	var (
		uErr   error
		pChain []string
	)
	pKeyPEM, leafPEM, pChain, uErr = unpackPkcs12(enrollResponse.CertificateInformation.PKCS12Blob, lookupPassword)
	chainPEM = strings.Join(pChain, "\n")

	if uErr != nil {
		tflog.Error(ctx, "Error unpacking PKCS12 blob, attempting to recover private key.")
		//attempt to recover private key
		rErr := diag.Diagnostics{}
		pKeyPEM, leafPEM, chainPEM, rErr = recoverPrivateKeyFromKeyfactorCommand(
			ctx, enrolledId,
			collectionIdInt, lookupPassword, r.p.client,
		)
		diags.Append(rErr...)
		if diags.HasError() {
			diags.AddError(
				"Private key recovery failed.",
				"Could not recover private key from Keyfactor Command: "+uErr.Error(),
			)
			return nil, diags
		}
	}

	// Set state
	tflog.Info(
		ctx,
		fmt.Sprintf("Setting state for certificate '%s'(%d).", PFXArgs.Subject.SubjectCommonName, enrolledId),
	)
	tflog.Debug(ctx, "Creating state object")

	plan.IsPendingRevocation.Unknown = false
	plan.IsExpired.Unknown = false
	plan.IsRevoked.Unknown = false
	var result = CommandCertificate{
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
		PEM:                  types.String{Value: leafPEM},
		PEMCACert:            types.String{Value: chainPEM},
		PEMChain:             types.String{Value: chainPEM},
		PrivateKey:           types.String{Value: pKeyPEM},
		KeyPassword:          plan.KeyPassword,
		CertificateAuthority: plan.CertificateAuthority,
		CertificateTemplate:  plan.CertificateTemplate,
		CertificateId:        types.Int64{Value: int64(enrolledId)},
		RequestId:            types.Int64{Value: int64(enrollResponse.CertificateInformation.KeyfactorRequestID)},
		Metadata:             plan.Metadata,
		CollectionId:         plan.CollectionId,
		FriendlyName:         plan.FriendlyName,
		UseCNAsFriendlyName:  plan.UseCNAsFriendlyName,
		ExpiryWarningDays:    plan.ExpiryWarningDays,
		IsExpired:            plan.IsExpired,
		IsRevoked:            plan.IsRevoked,
		IsPendingRevocation:  plan.IsPendingRevocation,
		RenewalConfig:        plan.RenewalConfig,
	}

	return &result, diags
}

func (r resourceCommandCertificate) parseSans(ctx context.Context, plan *CommandCertificate) (
	[]string, []string,
	[]string, diag.Diagnostics,
) {
	var dnsSANs []string
	var ipSANs []string
	var uriSANs []string
	diags := diag.Diagnostics{}

	tflog.Debug(ctx, fmt.Sprintf("Parsing DNS SANs: %s", plan.DNSSANs))
	diags = plan.DNSSANs.ElementsAs(ctx, &dnsSANs, true)
	tflog.Debug(ctx, fmt.Sprintf("Parsing IP SANs: %s", plan.IPSANs))
	diags = plan.IPSANs.ElementsAs(ctx, &ipSANs, true)
	tflog.Debug(ctx, fmt.Sprintf("Parsing URI SANs: %s", plan.URISANs))
	diags = plan.URISANs.ElementsAs(ctx, &uriSANs, true)

	return dnsSANs, ipSANs, uriSANs, diags
}

func (r resourceCommandCertificate) parseMetadata(
	ctx context.Context,
	plan *CommandCertificate,
) (map[string]interface{}, diag.Diagnostics) {
	// iterate over metadata map and convert to map[string]interface{}
	tflog.Debug(ctx, fmt.Sprintf("Parsing metadata: %s", plan.Metadata))
	metaDataElms := plan.Metadata.Elems
	metadata := make(map[string]interface{})
	for k, elm := range metaDataElms {
		metadata[k] = strings.Replace(elm.String(), "\"", "", -1)
	}
	return metadata, nil
}

func (r resourceCommandCertificate) enrollCSR(
	ctx context.Context, csr string,
	plan *CommandCertificate,
) (
	*CommandCertificate,
	diag.Diagnostics,
) {
	//ensure that conflicting values are not set
	diags := diag.Diagnostics{}
	if plan.CommonName.Value != "" || plan.Organization.Value != "" || plan.OrganizationalUnit.Value != "" || plan.Locality.Value != "" || plan.State.Value != "" || plan.Country.Value != "" || plan.PrivateKey.Value != "" || plan.KeyPassword.Value != "" {
		diags.AddError(
			ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE,
			"You cannot set the private_key, password, common_name, organization, organizational_unit, locality, state, or country when using a CSR.",
		)
		return nil, diags
	}

	tflog.Debug(ctx, "Calling parseSans()")
	dnsSANs, ipSANs, uriSANs, dnsSANsDiags := r.parseSans(ctx, plan)
	if dnsSANsDiags.HasError() {
		diags.Append(dnsSANsDiags...)
	}

	metadata, metadataDiags := r.parseMetadata(ctx, plan)
	if metadataDiags.HasError() {
		diags.Append(metadataDiags...)
	}

	tflog.Debug(ctx, "Creating certificate from CSR.")
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
	enrollResponse, err := r.p.client.EnrollCSR(CSRArgs)
	if err != nil {
		diags.AddError(
			ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE,
			"Could not create certificate in Keyfactor: "+err.Error(),
		)
		return nil, diags
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
	var result = CommandCertificate{
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
		FriendlyName:         plan.FriendlyName,
		UseCNAsFriendlyName:  plan.UseCNAsFriendlyName,
		ExpiryWarningDays:    plan.ExpiryWarningDays,
		IsExpired:            plan.IsExpired,
		IsRevoked:            plan.IsRevoked,
		IsPendingRevocation:  plan.IsPendingRevocation,
		RenewalConfig:        plan.RenewalConfig,
	}

	return &result, diags
}
