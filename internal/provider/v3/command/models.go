package command

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type CertificateDataSourceModel struct {
	Id                       types.Int64                       `json:"Id" tfsdk:"certificate_id"` // modified
	Thumbprint               types.String                      `json:"Thumbprint" tfsdk:"thumbprint"`
	SerialNumber             types.String                      `json:"SerialNumber" tfsdk:"serial_number"`
	IssuedDN                 types.String                      `json:"IssuedDN" tfsdk:"issued_dn"`
	IssuedCN                 types.String                      `json:"IssuedCN" tfsdk:"issued_cn"`
	ImportDate               types.String                      `json:"ImportDate,omitempty" tfsdk:"import_date"`
	NotBefore                types.String                      `json:"NotBefore,omitempty" tfsdk:"not_before"`
	NotAfter                 types.String                      `json:"NotAfter,omitempty" tfsdk:"not_after"`
	IssuerDN                 types.String                      `json:"IssuerDN,omitempty" tfsdk:"issuer_dn"`
	PrincipalId              types.Int64                       `json:"PrincipalId,omitempty" tfsdk:"principal_id"`
	TemplateId               types.Int64                       `json:"TemplateId,omitempty" tfsdk:"template_id"`
	CertState                types.String                      `json:"CertStateString,omitempty" tfsdk:"cert_state"`
	KeySizeInBits            types.Int64                       `json:"KeySizeInBits" tfsdk:"key_bits"`
	KeyType                  types.String                      `json:"KeyTypeString" tfsdk:"key_type"`
	RequesterId              types.Int64                       `json:"RequesterId" tfsdk:"requester_id"`
	IssuedOU                 types.String                      `json:"IssuedOU" tfsdk:"issued_ou"`
	IssuedEmail              types.String                      `json:"IssuedEmail" tfsdk:"issued_email"`
	KeyUsage                 types.Int64                       `json:"KeyUsage" tfsdk:"key_usage"`
	SigningAlgorithm         types.String                      `json:"SigningAlgorithm" tfsdk:"signing_algorithm"`
	RevocationEffDate        types.String                      `json:"RevocationEffDate" tfsdk:"revocation_effective_date"`
	RevocationReason         types.Int64                       `json:"RevocationReason" tfsdk:"revocation_reason"`
	RevocationComment        types.String                      `json:"RevocationComment" tfsdk:"revocation_comment"`
	CertificateAuthorityId   types.Int64                       `json:"CertificateAuthorityId" tfsdk:"certificate_authority_id"`
	CertificateAuthorityName types.String                      `json:"CertificateAuthorityName" tfsdk:"certificate_authority"` //modified
	TemplateName             types.String                      `json:"TemplateName" tfsdk:"certificate_template"`              //modified
	ArchivedKey              types.Bool                        `json:"ArchivedKey" tfsdk:"archived_key"`
	HasPrivateKey            types.Bool                        `json:"HasPrivateKey" tfsdk:"has_private_key"`
	PrincipalName            types.String                      `json:"PrincipalName" tfsdk:"principal_name"`
	CertRequestId            types.Int64                       `json:"CertRequestId" tfsdk:"command_request_id"` // modified
	RequesterName            types.String                      `json:"RequesterName" tfsdk:"requester_name"`
	ContentBytes             types.String                      `json:"ContentBytes" tfsdk:"content_bytes"`
	ExtendedKeyUsages        []CertificateExtendedKeyUsage     `json:"ExtendedKeyUsages" tfsdk:"extended_key_usage"`
	SubjectAltNameElements   []CertificateSubjectAltName       `json:"SubjectAltNameElements" tfsdk:"subject_alt_name_element"`
	CRLDistributionPoints    []CertificateCRLDistributionPoint `json:"CRLDistributionPoints" tfsdk:"crl_distribution_point"`
	LocationsCount           []CertificateLocationCount        `json:"LocationsCount" tfsdk:"locations_count"`
	SSLLocations             []CertificateSSLLocation          `json:"SSLLocations" tfsdk:"ssl_location"`
	Locations                []CertificateLocation             `json:"Locations" tfsdk:"location"`
	Metadata                 types.Map                         `json:"Metadata" tfsdk:"metadata"`
	CertificateKeyId         types.Int64                       `json:"CertificateKeyId" tfsdk:"certificate_key_id"`
	CARowIndex               types.Int64                       `json:"CARowIndex" tfsdk:"ca_row_index"`
	CARecordId               types.String                      `json:"CARecordId" tfsdk:"ca_record_id"`
	DetailedKeyUsage         *CertificateDetailedKeyUsage      `json:"DetailedKeyUsage" tfsdk:"detailed_key_usage"`
	KeyRecoverable           types.Bool                        `json:"KeyRecoverable" tfsdk:"key_recoverable"`
	Curve                    types.String                      `json:"Curve" tfsdk:"curve"`
	// TF specific fields
	Identifier        types.String `tfsdk:"identifier"`
	PEM               types.String `tfsdk:"certificate_pem"`
	PEMChain          types.String `tfsdk:"certificate_chain"`
	PrivateKey        types.String `tfsdk:"private_key"`
	KeyPassword       types.String `tfsdk:"key_password"`
	DNSSANs           types.List   `tfsdk:"dns_sans"`
	IPSANs            types.List   `tfsdk:"ip_sans"`
	URISANs           types.List   `tfsdk:"uri_sans"`
	IncludePrivateKey types.Bool   `tfsdk:"include_private_key"`
	CollectionId      types.Int64  `tfsdk:"collection_id"`
}

type CertificateExtendedKeyUsage struct {
	Id          types.Int64  `json:"Id" tfsdk:"id"`
	Oid         types.String `json:"Oid" tfsdk:"oid"`
	DisplayName types.String `json:"DisplayName" tfsdk:"display_name"`
}

type CertificateSubjectAltName struct {
	Id        types.Int64  `json:"Id" tfsdk:"id"`
	Value     types.String `json:"Value" tfsdk:"value"`
	Type      types.Int64  `json:"Type" tfsdk:"san_type"`
	ValueHash types.String `json:"ValueHash" tfsdk:"value_hash"`
}

type CertificateCRLDistributionPoint struct {
	Id      types.Int64  `json:"Id" tfsdk:"id"`
	Url     types.String `json:"Url" tfsdk:"url"`
	UrlHash types.String `json:"UrlHash" tfsdk:"url_hash"`
}

type CertificateLocationCount struct {
	StoreType types.String `json:"Type" tfsdk:"store_type"`
	Count     types.Int64  `json:"Count" tfsdk:"count"`
}

type CertificateSSLLocation struct {
	StorePath   types.String `json:"StorePath" tfsdk:"store_path"`
	AgentPool   types.String `json:"AgentPool" tfsdk:"agent_pool"`
	IPAddress   types.String `json:"IPAddress" tfsdk:"ip_address"`
	Port        types.Int64  `json:"Port" tfsdk:"port"`
	NetworkName types.String `json:"NetworkName" tfsdk:"network_name"`
}

type CertificateLocation struct {
	StoreMachineName types.String `json:"StoreMachineName" tfsdk:"store_machine_name"`
	StorePath        types.String `json:"StorePath" tfsdk:"store_path"`
	StoreType        types.Int64  `json:"StoreType" tfsdk:"store_type"`
	Alias            types.String `json:"Alias" tfsdk:"alias"`
	ChainLevel       types.Int64  `json:"ChainLevel" tfsdk:"chain_level"`
	CertStoreId      types.String `json:"CertStoreId" tfsdk:"cert_store_id"`
}

type CertificateDetailedKeyUsage struct {
	CrlSign          types.Bool   `json:"CrlSign" tfsdk:"crl_sign"`
	DataEncipherment types.Bool   `json:"DataEncipherment" tfsdk:"data_encipherment"`
	DecipherOnly     types.Bool   `json:"DecipherOnly" tfsdk:"decipher_only"`
	DigitalSignature types.Bool   `json:"DigitalSignature" tfsdk:"digital_signature"`
	EncipherOnly     types.Bool   `json:"EncipherOnly" tfsdk:"encipher_only"`
	KeyAgreement     types.Bool   `json:"KeyAgreement" tfsdk:"key_agreement"`
	KeyCertSign      types.Bool   `json:"KeyCertSign" tfsdk:"key_cert_sign"`
	KeyEncipherment  types.Bool   `json:"KeyEncipherment" tfsdk:"key_encipherment"`
	NonRepudiation   types.Bool   `json:"NonRepudiation" tfsdk:"non_repudiation"`
	HexCode          types.String `json:"HexCode" tfsdk:"hex_code"`
}
