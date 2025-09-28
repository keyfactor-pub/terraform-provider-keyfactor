// Package keyfactor provides Terraform provider functionality for interacting with Keyfactor Command
// for certificate lifecycle management.
package keyfactor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// dataSourceCertificateType defines a data source for retrieving certificate-related
// information from Keyfactor Command.
//
// This data source allows users to query and inspect certificate attributes such
// as the subject name, locality, organization, state, country, and more.
type dataSourceCertificateType struct{}

// GetSchema defines the schema for the data source. It specifies the attributes
// available for use within the data source, their types, and metadata.
//
// Attributes:
//   - csr: Base-64 encoded certificate signing request (CSR).
//   - key_password: Password used to recover a private key from Keyfactor Command. If no value
//     is provided, a random password will be generated for key recovery.
//   - common_name: Subject common name (CN) of the certificate.
//   - locality: Subject locality (L) of the certificate.
//   - organization: Subject organization (O) of the certificate.
//   - state: Subject state (ST) of the certificate.
//   - country: Subject country (C) of the certificate.
//   - organizational_unit: Subject organizational unit (OU) of the certificate.
//   - certificate_authority: Name of the certificate authority (CA) to deploy the certificate with.
//   - certificate_template: Short name of the certificate template to be used.
//   - dns_sans: List of DNS subject alternative names (DNS SANs) associated with the certificate.
//   - uri_sans: List of URI subject alternative names (URI SANs) associated with the certificate.
//
// Returns:
//   - tfsdk.Schema: The defined schema for the data source.
//   - diag.Diagnostics: Any diagnostics encountered in the schema generation process.
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
			"use_cn_as_friendly_name": {
				Type:     types.BoolType,
				Computed: true,
				Description: "Only applicable for PFX enrollments. Use the common name as the friendly name for the" +
					" certificate. Defaults to `true`. " +
					"NOTE: Keyfactor Command must be configured to `allow custom friendly name` for this to work" +
					" under `Application Settings > Enrollment > PFX`.",
				Optional:      true,
				PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.RequiresReplace()},
			},
			"friendly_name": {
				Type:     types.StringType,
				Computed: true,
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
									func(ctx context.Context, state attr.Value, config attr.Value, path path.Path) (
										bool,
										diag.Diagnostics,
									) {
										var diags diag.Diagnostics

										// Check if the planned value (config) is valid and known
										//plannedValue, _ := config.ToTerraformValue(ctx)
										//var stateValue bool
										//pErr := plannedValue.As(&stateValue)
										//if pErr != nil {
										//	diags.AddError(
										//		"Value conversion error",
										//		"Unable to convert value to bool",
										//	)
										//	return false, diags
										//}
										planVal, err := config.ToTerraformValue(ctx)
										if err != nil {
											diags.AddError(
												"Value conversion error",
												"Unable to convert value to bool",
											)
										}

										var forceRenewal bool
										convErr := planVal.As(&forceRenewal)
										if convErr != nil {
											diags.AddError(
												"Value conversion error",
												"Unable to convert value to bool",
											)
											return false, diags
										}

										if forceRenewal {
											return true, diags
										}

										return false, diags
									},
									"Triggers resource replacement when force_renewal is set to true.",     // Description
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
		Description:         "Reads an existing certificate from Keyfactor Command using the `/Certificates` API",
		MarkdownDescription: `Reads an existing certificate from Keyfactor Command using the "/Certificates" API.`,
	}, nil
}

// NewDataSource initializes and returns a new instance of the `dataSourceCertificate` with the provided provider.
func (r dataSourceCertificateType) NewDataSource(ctx context.Context, p tfsdk.Provider) (
	tfsdk.DataSource,
	diag.Diagnostics,
) {
	return dataSourceCertificate{
		p: *(p.(*provider)),
	}, nil
}

// dataSourceCertificate represents a data source for retrieving certificate-related information from the provider.
type dataSourceCertificate struct {
	p provider
}

// Read executes the "read" operation for the data source. This method is called
// to query for data from Keyfactor Command and populate the attributes defined in the schema.
//
// Inputs:
// - ctx (context.Context): The context for the read operation, used for logging or other context-sensitive tasks.
// - req (tfsdk.ReadDataSourceRequest): The request object containing input data for the read operation.
// - resp (tfsdk.ReadDataSourceResponse): The response object used to send data back to Terraform.
//
// Behavior:
//   - The Read method retrieves the certificate data from the Keyfactor Command API
//     based on input criteria and sets the results into the response object as resource attributes.
func (r dataSourceCertificate) Read(
	ctx context.Context,
	request tfsdk.ReadDataSourceRequest,
	response *tfsdk.ReadDataSourceResponse,
) {
	var state CommandCertificate
	tflog.Info(ctx, "Reading terraform data resource 'certificate'.")

	// Extract initial config into state and append errors if necessary
	response.Diagnostics.Append(request.Config.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
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

	if certGetResp != nil {
		certificateID = certGetResp.Id
	}

	// Attempt to recover or download certificate from Command
	leafPEM, chainPEM, pKeyPEM, rawData, rDiags := recoverOrDownloadCertificate(
		ctx,
		certificateID,
		collectionIdInt,
		state.KeyPassword.Value,
		r.p.client,
		state.CertificateFormat.Value,
	)

	// Handle leaf PEM encoding for certificates without private keys
	if certGetResp != nil && leafPEM == "" {
		if certGetResp.ContentBytes == "" && rawData != nil {
			leafPEM, _ = encodeCertificate(ctx, *rawData, certificateID)
		} else {
			leafPEM, _ = encodeCertificate(ctx, certGetResp.ContentBytes, certificateID)
		}

	}

	if leafPEM == "" {
		response.Diagnostics.Append(rDiags...)
		if !rDiags.HasError() {
			response.Diagnostics.AddError(
				ERR_SUMMARY_CERTIFICATE_RESOURCE_READ,
				fmt.Sprintf(
					"Failed to retrieve certificate '%s' from Keyfactor Command. "+
						"Please check the certificate ID and try again.", state.ID.Value,
				),
			)
		}

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
		fullChain = leafPEM + "\n" + chainPEM
	}

	caName := state.CertificateAuthority.Value
	templateName := state.CertificateTemplate.Value
	metadata := state.Metadata

	var warningDays int
	if state.ExpiryWarningDays.Null || state.ExpiryWarningDays.Unknown {
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
	revoked, expired, _, cDiags = checkCertDiags(ctx, certGetResp, warningDays, leaf)
	response.Diagnostics.Append(cDiags...)

	if certGetResp != nil {
		caName = certGetResp.CertificateAuthorityName
		certificateID = certGetResp.Id
		templateName = certGetResp.TemplateName
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
		ID:           state.ID,
		CSR:          state.CSR,
		CommonName:   types.String{Value: leaf.Subject.CommonName, Null: false},
		Locality:     types.String{Value: strings.Join(leaf.Subject.Locality, ","), Null: false},
		State:        types.String{Value: strings.Join(leaf.Subject.Province, ","), Null: false},
		Country:      types.String{Value: strings.Join(leaf.Subject.Country, ","), Null: false},
		Organization: types.String{Value: strings.Join(leaf.Subject.Organization, ","), Null: false},
		OrganizationalUnit: types.String{
			Value: strings.Join(leaf.Subject.OrganizationalUnit, ","),
			Null:  false,
		},
		DNSSANs:      DNSSANStoTerraform(leaf.DNSNames, false),
		IPSANs:       IPSANStoTerraform(leaf.IPAddresses, false),
		URISANs:      URISANStoTerraform(leaf.URIs, false),
		SerialNumber: types.String{Value: sn, Null: isNullString(sn)},
		IssuerDN:     types.String{Value: issuerDN, Null: isNullString(issuerDN)},
		Thumbprint:   types.String{Value: tp, Null: isNullString(tp)},
		PEM:          types.String{Value: leafPEM, Null: isNullString(leafPEM)},
		PEMCACert:    types.String{Value: chainPEM, Null: isNullString(chainPEM)},
		PEMChain:     types.String{Value: fullChain, Null: isNullString(fullChain)},
		PrivateKey:   types.String{Value: pKeyPEM, Null: isNullString(pKeyPEM)},
		KeyPassword:  state.KeyPassword,
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
	diags := response.State.Set(ctx, &result)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

}

//// processCertificate handles the main logic for recovering or downloading certificates.
//func processCertificate(
//	ctx context.Context,
//	context *api.GetCertificateContext,
//	id, collectionID int,
//	password string,
//	client *api.Client,
//) (leaf x509.Certificate, leafPEM, chainPEM, pKeyPEM string, metadata types.Map, diagnostics diag.Diagnostics) {
//	if context == nil && id > UNKNOWN_CERTIFICATE_ID {
//		leafPEM, chainPEM, pKeyPEM, metadata = recoverOrDownloadCertificate(
//			ctx,
//			id,
//			collectionID,
//			password,
//			client,
//			diags,
//		)
//	} else if context != nil {
//		// Process certificate from context
//		certBytes, decodeErr := base64.StdEncoding.DecodeString(context.ContentBytes)
//		if diags.HasError() {
//			return
//		}
//		leaf = x509.Certificate{Raw: certBytes}
//		metadata = flattenMetadata(context.Metadata)
//	}
//	return
//}
