package command

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	kfc "github.com/Keyfactor/keyfactor-go-client-sdk/v2/api/command"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"net/http"
	"strconv"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &CertificateDataSource{}

func NewCertificateDataSource() datasource.DataSource {
	return &CertificateDataSource{}
}

// CertificateDataSource defines the data source implementation.
type CertificateDataSource struct {
	provider *Provider
	client   *kfc.APIClient
}

func (d *CertificateDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "keyfactor_certificate"
}

func (d *CertificateDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Example data source",

		Attributes: map[string]schema.Attribute{
			//"configurable_attribute": schema.StringAttribute{
			//	MarkdownDescription: "Example configurable attribute",
			//	Optional:            true,
			//},
			"certificate_id": schema.Int64Attribute{
				MarkdownDescription: "This is the unique identifier for the certificate in Keyfactor Command.",
				Computed:            true,
			},
			"identifier": schema.StringAttribute{
				Required:  true,
				Optional:  false,
				Computed:  false,
				Sensitive: false,
				Description: "Keyfactor Command certificate identifier. This can be any of the following values: thumbprint, CN, " +
					"or Keyfactor Command Certificate ID. If using CN to lookup the last issued certificate, the CN must " +
					"be an exact match and if multiple certificates are returned the certificate that was most recently " +
					"issued will be returned. ",
				MarkdownDescription: "Keyfactor Command certificate identifier. This can be any of the following values: thumbprint, CN, " +
					"or Keyfactor Command Certificate ID. If using CN to lookup the last issued certificate, the CN must " +
					"be an exact match and if multiple certificates are returned the certificate that was most recently " +
					"issued will be returned. ",
				DeprecationMessage: "",
				Validators:         nil,
			},
			"thumbprint": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the thumbprint of the certificate.",
			},
			"serial_number": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the serial number of the certificate.",
			},
			"issued_dn": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the issued distinguished name of the certificate.",
			},
			"issued_cn": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the issued common name of the certificate.",
			},
			"import_date": schema.StringAttribute{
				Computed:    true,
				Description: "The date, in UTC, on which the certificate was imported into Keyfactor Command.",
			},
			"not_before": schema.StringAttribute{
				Computed:    true,
				Description: "The date, in UTC, on which the certificate was issued by the certificate authority.",
			},
			"not_after": schema.StringAttribute{
				Computed:    true,
				Description: "The date, in UTC, on which the certificate expires.",
			},
			"issuer_dn": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the distinguished name of the certificate authority that issued the certificate.",
			},
			"principal_id": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the Keyfactor Command reference ID of the principal (UPN) that requested the certificate. Typically, this field is only populated for end user certificates requested through Keyfactor Command (e.g. Mac auto-enrollment certificates). See also PrinicpalName.",
			},
			"template_id": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the Keyfactor Command reference ID of the template associated with the certificate.",
			},
			"cert_state": schema.StringAttribute{
				Computed:    true,
				Description: "An integer specifying the state of the certificate.",
				MarkdownDescription: `
	An integer specifying the state of the certificate. The following values are possible:
	| Value | Description |
	|-------|-------------|
	| 0 | Unknown |
	| 1 | Active |
	| 2 | Revoked |
	| 3 | Denied |
	| 4 | Failed |
	| 5 | Pending |
	| 6 | Certificate Authority |
	| 7 | Parent Certificate Authority |
	`,
			},
			"key_bits": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer specifying the key size in bits.",
			},
			"key_type": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the type of key.",
			},
			"requester_id": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the Keyfactor Command reference ID of the requester (UPN) that requested the certificate. Typically, this field is only populated for end user certificates requested through Keyfactor Command (e.g. Mac auto-enrollment certificates). See also RequesterName.",
			},
			"issued_ou": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the issued organizational unit of the certificate.",
			},
			"issued_email": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the email address of the certificate.",
			},
			"key_usage": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the total key usage of the certificate. Key usage is stored in Active Directory as a single value made of a combination of values. ",
				MarkdownDescription: `
	An integer indicating the total key usage of the certificate. Key usage is stored in Active Directory as a single value made of a combination of values. The following values are possible:
	| Value | Function | Description |
	|-------|----------|-------------|
	| 0 | None | No key usage |
	| 1 | EncipherOnly | The key can be used for encryption only. |
	| 2 | CRL Signing | The key can be used to sign a certificate revocation list (CRL). |
	| 4 | Key CertSign | The key can be used to sign certificates. |
	| 8 | Key Agreement | The key can be used for key agreement. |
	| 16 | Data Encipherment | The key can be used for data encryption. |
	| 32 | Key Encipherment | The key can be used for key encryption. |
	| 64 | Non Repudiation | The key can be used for authentication. |
	| 128 | Digital Signature | The key can be used for digital signatures. |
	| 32768 | Decipherment Only | The key can be used for decryption only. |
	
	For example, a value of 160 would represent a key usage of digital signature with key encipherment. A value of 224 would add nonrepudiation to those.
	`,
			},
			"signing_algorithm": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the signing algorithm of the certificate.",
			},
			"revocation_effective_date": schema.StringAttribute{
				Computed:    true,
				Description: "The date, in UTC, on which the certificate was revoked.",
			},
			"revocation_reason": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the reason the certificate was revoked.",
				MarkdownDescription: `
	An integer indicating the reason the certificate was revoked. The following values are possible:
	| Value | Description |
	|-------|-------------|
	| 0 | Unspecified |
	| 1 | Key Compromise |
	| 2 | CA Compromise |
	| 3 | Affiliation Changed |
	| 4 | Superseded |
	| 5 | Cessation of Operation |
	| 6 | Certificate Hold |
	| 999 | Unknown |
	`,
			},
			"revocation_comment": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the comment associated with the revocation of the certificate.",
			},
			"certificate_authority_id": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the Keyfactor Command reference ID of the certificate authority that issued the certificate.",
			},
			"certificate_authority": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the name of the certificate authority that issued the certificate.",
			},
			"certificate_template": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the name of the template associated with the certificate.",
			},
			"archived_key": schema.BoolAttribute{
				Computed:    true,
				Description: "A boolean indicating whether the certificate has been archived.",
			},
			"has_private_key": schema.BoolAttribute{
				Computed:    true,
				Description: "A boolean indicating whether the certificate has a private key.",
			},
			"principal_name": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the principal (UPN) that requested the certificate. Typically, this field is only populated for end user certificates requested through Keyfactor Command (e.g. Mac auto-enrollment certificates). See also PrincipalId.",
			},
			"command_request_id": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the Keyfactor Command reference ID of the certificate request associated with the certificate.",
			},
			"requester_name": schema.StringAttribute{
				Computed:    true,
				Description: "A string containing the name of the identity that requested the certificate.",
			},
			"content_bytes": schema.StringAttribute{
				Computed:    true,
				Description: "A string containing the certificate as bytes.",
			},
			"extended_key_usage": schema.ListNestedAttribute{
				Computed:    true,
				Description: "An array of objects containing the extended key usage of the certificate.",
				MarkdownDescription: `
	An array of objects containing the extended key usage of the certificate. Each object contains the following fields:
	| Field | Description |
	|-------|-------------|
	| Id | An integer indicating the Keyfactor Command reference ID of the extended key usage. |
	| Oid | A string indicating the object identifier (OID) of the extended key usage. |
	| DisplayName | A string indicating the display name of the extended key usage. |
	`,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"oid": schema.StringAttribute{
							Description: "A string indicating the object identifier (OID) of the extended key usage.",
							Computed:    true,
						},
						"display_name": schema.StringAttribute{
							Description: "A string indicating the display name of the extended key usage.",
							Computed:    true,
						},
						"id": schema.Int64Attribute{
							Description: "An integer indicating the Keyfactor Command reference ID of the extended key usage.",
							Computed:    true,
						},
					},
					CustomType: nil,
					Validators: nil,
				},
			},
			"subject_alt_name_element": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{},
				Computed:       true,
				Description:    "An array of objects containing the subject alternative name elements of the certificate.",
				MarkdownDescription: `
	An array of objects containing the subject alternative name elements of the certificate. Each object contains the following fields:
	| Field | Description |
	|-------|-------------|
	| Id | An integer indicating the Keyfactor Command reference ID of the subject alternative name element. |
	| Value | A string indicating the value of the subject alternative name element. |
	| Type | An integer indicating the type of the subject alternative name element. |
	| ValueHash | A string indicating the hash of the value of the subject alternative name element. |
	`,
			},
			"crl_distribution_point": schema.ListNestedAttribute{
				Computed:    true,
				Description: "An array of objects containing the certificate revocation list (CRL) distribution points of the certificate.",
				MarkdownDescription: `
	An array of objects containing the certificate revocation list (CRL) distribution points of the certificate. Each object contains the following fields:
	| Field | Description |
	|-------|-------------|
	| Id | An integer indicating the Keyfactor Command reference ID of the CRL distribution point. |
	| Url | A string indicating the URL of the CRL distribution point. |
	| UrlHash | A string indicating the hash of the URL of the CRL distribution point. |
	`,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Computed:    true,
							Description: "",
						},
						"url": schema.StringAttribute{
							Computed:    true,
							Description: "",
						},
						"url_hash": schema.StringAttribute{
							Computed:    true,
							Description: "",
						},
					},
				},
			},
			"locations_count": schema.ListNestedAttribute{
				Computed:    true,
				Description: "An array of objects containing the certificate locations of the certificate.",
				MarkdownDescription: `
	An array of objects containing the certificate locations of the certificate. Each object contains the following fields:
	| Field | Description |
	|-------|-------------|
	| Type | A string indicating the store type of the certificate location. |
	| Count | An integer indicating the number of certificates in the certificate location. |
	`,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"store_type": schema.StringAttribute{
							Computed:    true,
							Description: "",
						},
						"count": schema.Int64Attribute{
							Computed:    true,
							Description: "",
						},
					},
				},
			},
			"ssl_location": schema.ListNestedAttribute{
				Computed:    true,
				Description: "An array of objects containing the SSL locations where the certificate is found using SSL discovery.",
				MarkdownDescription: `
	An array of objects containing the SSL locations where the certificate is found using SSL discovery. Each object contains the following fields:
	| Field | Description |
	|-------|-------------|
	| StorePath | A string indicating the path of the SSL location. |
	| AgentPool | A string indicating the agent pool of the SSL location. |
	| IPAddress | A string indicating the IP address of the SSL location. |
	| Port | An integer indicating the port of the SSL location. |
	| NetworkName | A string indicating the network name of the SSL location. |
	`,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"store_path": schema.StringAttribute{
							Computed:    true,
							Description: "",
						},
						"agent_pool": schema.StringAttribute{
							Computed:    true,
							Description: "",
						},
						"ip_address": schema.StringAttribute{
							Computed:    true,
							Description: "",
						},
						"port": schema.Int64Attribute{
							Computed:    true,
							Description: "",
						},
						"network_name": schema.StringAttribute{
							Computed:    true,
							Description: "",
						},
					},
				},
			},
			"location": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{},
				Computed:       true,
				Description:    "An array of objects containing the certificate locations where the certificate is found using certificate store inventorying.",
				MarkdownDescription: `
	An array of objects containing the certificate locations where the certificate is found using certificate store inventorying. Each object contains the following fields:
	| Field | Description |
	|-------|-------------|
	| StoreMachineName | A string indicating the machine name of the certificate location. |
	| StorePath | A string indicating the path of the certificate location. |
	| StoreType | An integer indicating the type of the certificate location. |
	| Alias | A string indicating the alias of the certificate location. |
	| ChainLevel | An integer indicating the chain level of the certificate location. |
	| CertStoreId | A string indicating the certificate store ID of the certificate location. |
	`,
			},
			"metadata": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
			},
			"certificate_key_id": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer indicating the Keyfactor Command reference ID of the certificate key.",
			},
			"ca_row_index": schema.Int64Attribute{
				Computed:    true,
				Description: "An integer containing the CA's reference ID for certificate. Note:  The CARowIndex has been replaced by CARecordId, but will remain for backward compatibility. It will only contain a non-zero value for certificates issued by Microsoft CAs. For Microsoft CA certificates, the CARowIndex will be equal to the CARecordId value parsed to an integer.",
				MarkdownDescription: `
	An integer containing the CA's reference ID for certificate.
	| :exclamation: Note: The CARowIndex has been replaced by CARecordId, but will remain for backward compatibility. It will only contain a non-zero value for certificates issued by Microsoft CAs. For Microsoft CA certificates, the CARowIndex will be equal to the CARecordId value parsed to an integer. |
	|----------------------------------------------------------------------------------------------------------------|
	`,
			},
			"ca_record_id": schema.StringAttribute{
				Computed:    true,
				Description: "A string containing the CA's reference ID for certificate.",
			},
			"detailed_key_usage": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"crl_sign": schema.BoolAttribute{
						Computed: true,
					},
					"data_encipherment": schema.BoolAttribute{
						Computed: true,
					},
					"decipher_only": schema.BoolAttribute{
						Computed: true,
					},
					"digital_signature": schema.BoolAttribute{
						Computed: true,
					},
					"encipher_only": schema.BoolAttribute{
						Computed: true,
					},
					"hex_code": schema.StringAttribute{
						Computed: true,
					},
					"key_agreement": schema.BoolAttribute{
						Computed: true,
					},
					"key_cert_sign": schema.BoolAttribute{
						Computed: true,
					},
					"key_encipherment": schema.BoolAttribute{
						Computed: true,
					},
					"non_repudiation": schema.BoolAttribute{
						Computed: true,
					},
				},
				Description: "An array of objects containing the detailed key usage of the certificate.",
				MarkdownDescription: `
	An array of objects containing the detailed key usage of the certificate. Each object contains the following fields:
	| Field | Description |
	|-------|-------------|
	| CrlSign | A boolean indicating whether the key can be used to sign a certificate revocation list (CRL). |
	| DataEncipherment | A boolean indicating whether the key can be used for data encryption. |
	| DecipherOnly | A boolean indicating whether the key can be used for decryption only. |
	| DigitalSignature | A boolean indicating whether the key can be used for digital signatures. |
	| EncipherOnly | A boolean indicating whether the key can be used for encryption only. |
	| KeyAgreement | A boolean indicating whether the key can be used for key agreement. |
	| KeyCertSign | A boolean indicating whether the key can be used to sign certificates. |
	| KeyEncipherment | A boolean indicating whether the key can be used for key encryption. |
	| NonRepudiation | A boolean indicating whether the key can be used for authentication. |
	| HexCode | A string containing the hexadecimal code representing the total key usage. For example, a value of a0 would indicate digital signature with key encipherment. |
	`,
				Computed: true,
			},
			"key_recoverable": schema.BoolAttribute{
				Computed:    true,
				Description: "A boolean indicating whether the certificate key is recoverable.",
			},
			"curve": schema.StringAttribute{
				Computed:    true,
				Description: "A string indicating the curve of the certificate.",
				MarkdownDescription: `
	A string indicating the OID of the elliptic curve algorithm configured for the certificate, for ECC templates. Well-known OIDs include:
	- 1.2.840.10045.3.1.7 = P-256/prime256v1/secp256r1
	- 1.3.132.0.34 = P-384/secp384r1
	- 1.3.132.0.35 = P-521/secp521r1
	`,
			},
			"certificate_pem": schema.StringAttribute{
				Computed:    true,
				Description: "A string containing the certificate in PEM format.",
			},
			"certificate_chain": schema.StringAttribute{
				Computed:    true,
				Description: "A string containing the certificate chain in PEM format.",
			},
			"private_key": schema.StringAttribute{
				Computed:    true,
				Description: "A string containing the private key in PEM format.",
				Sensitive:   true,
			},
			"key_password": schema.StringAttribute{
				Optional:    true,
				Description: "A string containing the password to encrypt the private key with.",
				Sensitive:   true,
			},
			"ip_sans": schema.ListAttribute{
				Computed:    true,
				Description: "An array of strings containing the IP subject alternative names of the certificate.",
				ElementType: types.StringType,
			},
			"dns_sans": schema.ListAttribute{
				Computed:    true,
				Description: "An array of strings containing the DNS subject alternative names of the certificate.",
				ElementType: types.StringType,
			},
			"uri_sans": schema.ListAttribute{
				Computed:    true,
				Description: "An array of strings containing the URI subject alternative names of the certificate.",
				ElementType: types.StringType,
			},
			"include_private_key": schema.BoolAttribute{
				Computed:    false,
				Description: "A boolean indicating whether the private key should be retrieved from Keyfactor Command. Defaults to 'true'.",
				Optional:    true,
			},
			"collection_id": schema.Int64Attribute{
				Computed:    false,
				Description: "An integer indicating the Keyfactor Command reference ID of the collection to search for the certificate. Defaults to '0'.",
				Optional:    true,
			},
		},
	}

	//resp.Schema = CertificateDataSourceSchema(ctx) // this points to the generated provider schema
}

func (d *CertificateDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*kfc.APIClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *kfc.APIClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *CertificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CertificateDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	certIdentifier := data.Identifier.ValueString()
	collectionId := data.CollectionId.ValueInt64()
	ctx = tflog.SetField(ctx, "certificate_identifier", certIdentifier)

	// If the `identifier` attribute is an integer, use it to query the certificate
	var (
		clientResp *kfc.ModelsCertificateRetrievalResponse
		httpResp   *http.Response
		respErr    error
	)

	if cID, ok := strconv.Atoi(certIdentifier); ok == nil {
		clientResp, httpResp, respErr = readCertificateById(ctx, cID, d.client, collectionId)
	} else if len(certIdentifier) == CertificateThumbprintLength {
		clientResp, httpResp, respErr = lookupCertificate(ctx, CertificateThumbprintFieldName, certIdentifier, d.client, collectionId)
	} else {
		clientResp, httpResp, respErr = lookupCertificate(ctx, CertificateCNFieldName, certIdentifier, d.client, collectionId)
	}
	if clientResp == nil {
		resp.Diagnostics.AddError("Invalid Certificate Identifier", fmt.Sprintf("Unable to find certificate %s in Keyfactor Command", certIdentifier))
		return
	} else if respErr != nil {
		ctx = tflog.SetField(ctx, "api_response", httpResp)
		ctx = tflog.SetField(ctx, "api_error", respErr)
		tflog.Error(ctx, "Unable to lookup certificate on Keyfactor Command")
		resp.Diagnostics.AddError("Certificate Lookup Error", respErr.Error())
		return
	}

	certPEM, ipSANs, dnsSANs, uriSANs, sanErr := ParseCertificateBytes(clientResp.ContentBytes)
	if sanErr != nil {
		tflog.Error(ctx, fmt.Sprintf("Unable to parse certificate SANs: %v", sanErr))
		resp.Diagnostics.AddError("SAN Parse Error", fmt.Sprintf("Unable to parse certificate SANs: %v", sanErr))
	}
	tflog.Debug(ctx, fmt.Sprintf("IP SANs: %v", ipSANs))
	tflog.Debug(ctx, fmt.Sprintf("DNS SANs: %v", dnsSANs))
	tflog.Debug(ctx, fmt.Sprintf("URI SANs: %v", uriSANs))

	if clientResp.KeyRecoverable != nil && *clientResp.KeyRecoverable {
		tflog.Info(ctx, fmt.Sprintf("private key is recoverable for certificate '%s', attempting recovery", certIdentifier))
		tflog.Debug(ctx, fmt.Sprintf("KeyRecoverable: %v", *clientResp.KeyRecoverable))
		cId := int64(*clientResp.Id)
		tflog.Debug(ctx, fmt.Sprintf("Calling RecoverPrivateKey for certificate '%d'", cId))
		pKey, leaf, chain, kErr := d.RecoverPrivateKey(ctx, cId, "", "", "", data.KeyPassword.String(), data.CollectionId.ValueInt64Pointer())
		if kErr != nil {
			tflog.Error(ctx, fmt.Sprintf("Unable to recover private key: %v", kErr))
			resp.Diagnostics.AddError("Private Key Recovery Error", fmt.Sprintf("Unable to recover private key: %v", kErr))
		}
		//tflog.Debug(ctx, fmt.Sprintf("Recovered private key: %v", pKey))
		tflog.SetField(ctx, "certificate_pem", leaf)
		tflog.SetField(ctx, "certificate_chain", chain)
		//tflog.SetField(ctx, "private_key", pKey)
		tflog.Debug(ctx, "Recovered certificate private key from Keyfactor Command.")
		data.PrivateKey = types.StringValue(pKey.(string))

		var chainStr string
		for _, cert := range chain {
			chainLink := string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}))
			chainStr = chainStr + chainLink
			tflog.Debug(ctx, chainLink)
		}

		data.PEMChain = types.StringValue(chainStr)
	}

	// Set the data model values from the response
	data.Id = types.Int64Value(convertInt64Ptr(clientResp.Id))
	data.Thumbprint = types.StringValue(convertStringPtr(clientResp.Thumbprint))
	data.SerialNumber = types.StringValue(convertStringPtr(clientResp.SerialNumber))
	data.IssuedDN = types.StringValue(convertNullableStringPtr(&clientResp.IssuedDN))
	data.IssuedCN = types.StringValue(convertNullableStringPtr(&clientResp.IssuedCN))
	data.ImportDate = types.StringValue(convertTimeToStringPtr(clientResp.ImportDate))
	data.NotBefore = types.StringValue(convertTimeToStringPtr(clientResp.NotBefore))
	data.NotAfter = types.StringValue(convertTimeToStringPtr(clientResp.NotAfter))
	data.IssuerDN = types.StringValue(convertNullableStringPtr(&clientResp.IssuerDN))
	data.PrincipalId = types.Int64Value(convertNullableIntPtr(&clientResp.PrincipalId))
	data.TemplateId = types.Int64Value(convertNullableIntPtr(&clientResp.TemplateId))
	data.CertState = types.StringValue(convertStringPtr(clientResp.CertStateString))
	data.KeySizeInBits = types.Int64Value(convertInt64Ptr(clientResp.KeySizeInBits))
	data.KeyType = types.StringValue(convertStringPtr(clientResp.KeyTypeString))
	data.RequesterId = types.Int64Value(int64(*clientResp.RequesterId))
	data.IssuedOU = types.StringValue(convertNullableStringPtr(&clientResp.IssuedOU))
	data.IssuedEmail = types.StringValue(convertNullableStringPtr(&clientResp.IssuedEmail))
	data.KeyUsage = types.Int64Value(convertInt64Ptr(clientResp.KeyUsage))
	data.SigningAlgorithm = types.StringValue(convertStringPtr(clientResp.SigningAlgorithm))
	data.RevocationEffDate = types.StringValue(convertNullableTimePtr(&clientResp.RevocationEffDate))
	data.RevocationReason = types.Int64Value(convertNullableIntPtr(&clientResp.RevocationReason))
	data.RevocationComment = types.StringValue(convertNullableStringPtr(&clientResp.RevocationComment))
	data.CertificateAuthorityId = types.Int64Value(convertInt64Ptr(clientResp.CertificateAuthorityId))
	data.CertificateAuthorityName = types.StringValue(convertStringPtr(clientResp.CertificateAuthorityName))
	data.TemplateName = types.StringValue(convertStringPtr(clientResp.TemplateName))
	data.ArchivedKey = types.BoolValue(*clientResp.ArchivedKey)
	data.HasPrivateKey = types.BoolValue(*clientResp.HasPrivateKey)
	data.PrincipalName = types.StringValue(convertNullableStringPtr(&clientResp.PrincipalName))
	data.CertRequestId = types.Int64Value(convertInt64Ptr(clientResp.CertRequestId))
	data.RequesterName = types.StringValue(*clientResp.RequesterName)
	data.ContentBytes = types.StringValue(convertStringPtr(clientResp.ContentBytes))

	data.CertificateKeyId = types.Int64Value(convertInt64Ptr(clientResp.CertificateKeyId))
	data.CARowIndex = types.Int64Value(*clientResp.CARowIndex)
	data.CARecordId = types.StringValue(convertStringPtr(clientResp.CARecordId))
	data.DetailedKeyUsage = d.setDetailedKeyUsage(clientResp.DetailedKeyUsage)
	data.KeyRecoverable = types.BoolValue(*clientResp.KeyRecoverable)
	data.Curve = types.StringValue(convertNullableStringPtr(&clientResp.Curve))

	data.ExtendedKeyUsages = d.setExtendedKeyUsage(clientResp.ExtendedKeyUsages)
	data.CRLDistributionPoints = d.setCRLEndpoints(clientResp.CRLDistributionPoints)
	data.LocationsCount = d.setLocationsCounts(clientResp.LocationsCount)

	data.IPSANs, _ = convertToTerraformList(ipSANs)
	data.DNSSANs, _ = convertToTerraformList(dnsSANs)
	data.URISANs, _ = convertToTerraformList(uriSANs)

	data.Metadata, _ = convertToTerraformMap(clientResp.Metadata)

	// Terraform Specific Values
	data.PEM = types.StringValue(certPEM)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *CertificateDataSource) convertJSONToTerraformModel(jsonString string) (*CertificateDataSourceModel, error) {
	var data CertificateDataSourceModel

	// read json string into data model
	jErr := json.Unmarshal([]byte(jsonString), &data)

	if jErr != nil {
		return nil, jErr
	}

	return &data, nil
}

//func (d *CertificateDataSource) setLocations(locations []kfc.ModelsCertificateRetrievalResponseCertificateStoreLocationDetailModel) []CertificateLocation {
//	var formattedLocations []CertificateLocation
//
//	if len(locations) > 0 {
//		for _, location := range locations {
//			certLocation := CertificateLocation{
//				StoreMachineName: types.StringValue(*location.),
//				StorePath:        types.StringValue(*location.StorePath),
//				StoreType:        types.StringValue(*location.StoreType),
//				Alias:            types.StringValue(*location.Alias),
//				ChainLevel:       types.Int64Value(int64(*location.ChainLevel)),
//				CertStoreId:      types.StringValue(*location.CertStoreId),
//			}
//			formattedLocations = append(formattedLocations, certLocation)
//		}
//	}
//	return formattedLocations
//}

func (d *CertificateDataSource) setLocationsCounts(locations []kfc.ModelsCertificateRetrievalResponseLocationCountModel) []CertificateLocationCount {
	var formattedLocations []CertificateLocationCount

	if len(locations) > 0 {
		for _, location := range locations {
			certLocation := CertificateLocationCount{
				StoreType: types.StringValue(*location.Type),
				Count:     types.Int64Value(int64(*location.Count)),
			}
			formattedLocations = append(formattedLocations, certLocation)
		}
	}
	return formattedLocations
}

func (d *CertificateDataSource) setDetailedKeyUsage(usage *kfc.ModelsCertificateRetrievalResponseDetailedKeyUsageModel) *CertificateDetailedKeyUsage {
	var formattedUsage CertificateDetailedKeyUsage

	if usage != nil {
		formattedUsage = CertificateDetailedKeyUsage{
			CrlSign:          types.BoolValue(*usage.CrlSign),
			DataEncipherment: types.BoolValue(*usage.DataEncipherment),
			DecipherOnly:     types.BoolValue(*usage.DecipherOnly),
			DigitalSignature: types.BoolValue(*usage.DigitalSignature),
			EncipherOnly:     types.BoolValue(*usage.EncipherOnly),
			KeyAgreement:     types.BoolValue(*usage.KeyAgreement),
			KeyCertSign:      types.BoolValue(*usage.KeyCertSign),
			KeyEncipherment:  types.BoolValue(*usage.KeyEncipherment),
			NonRepudiation:   types.BoolValue(*usage.NonRepudiation),
			HexCode:          types.StringValue(*usage.HexCode),
		}
	}
	return &formattedUsage
}

func (d *CertificateDataSource) setExtendedKeyUsage(usages []kfc.ModelsCertificateRetrievalResponseExtendedKeyUsageModel) []CertificateExtendedKeyUsage {
	var formattedUsages []CertificateExtendedKeyUsage

	if len(usages) > 0 {
		for _, usage := range usages {
			extKeyUsage := CertificateExtendedKeyUsage{
				Id:          types.Int64Value(int64(*usage.Id)),
				Oid:         types.StringValue(*usage.Oid),
				DisplayName: types.StringValue(*usage.DisplayName),
			}
			formattedUsages = append(formattedUsages, extKeyUsage)
		}
	}
	return formattedUsages
}

func (d *CertificateDataSource) setCRLEndpoints(crls []kfc.ModelsCertificateRetrievalResponseCRLDistributionPointModel) []CertificateCRLDistributionPoint {
	var formattedCRLs []CertificateCRLDistributionPoint

	if len(crls) > 0 {
		for _, crl := range crls {
			crlDistPoint := CertificateCRLDistributionPoint{
				Id:      types.Int64Value(int64(*crl.Id)),
				Url:     types.StringValue(*crl.Url),
				UrlHash: types.StringValue(*crl.UrlHash),
			}
			formattedCRLs = append(formattedCRLs, crlDistPoint)
		}
	}
	return formattedCRLs
}

func (d *CertificateDataSource) RecoverPrivateKey(ctx context.Context, id int64, thumbPrint string, sn string, dn string, password string, collectionID *int64) (interface{}, *x509.Certificate, []*x509.Certificate, error) {
	var colIDPtr *int32
	if collectionID != nil {
		colID := int32(*collectionID)
		colIDPtr = &colID
	}

	return recoverPrivateKey(ctx, d.client, id, thumbPrint, sn, dn, password, colIDPtr)
}
