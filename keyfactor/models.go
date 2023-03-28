package keyfactor

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Security Identity -
type SecurityIdentity struct {
	ID           types.Int64  `tfsdk:"id"`
	AccountName  types.String `tfsdk:"account_name"`
	Roles        types.List   `tfsdk:"roles"`
	IdentityType types.String `tfsdk:"identity_type"`
	Valid        types.Bool   `tfsdk:"valid"`
}

// Security Role -
type SecurityRole struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Permissions types.List   `tfsdk:"permissions"`
}

type KeyfactorCertificate struct {
	ID types.Int64 `tfsdk:"id"`
	// CSR Request Fields
	CSR types.String `tfsdk:"csr"`
	// PFX KfCertificate Fields
	Subject      types.Object `tfsdk:"subject"`
	DNSSANs      types.List   `tfsdk:"dns_sans"`
	IPSANs       types.List   `tfsdk:"ip_sans"`
	URISANs      types.List   `tfsdk:"uri_sans"`
	SerialNumber types.String `tfsdk:"serial_number"`
	IssuerDN     types.String `tfsdk:"issuer_dn"`
	Thumbprint   types.String `tfsdk:"thumbprint"`
	PEM          types.String `tfsdk:"certificate_pem"`
	PEMChain     types.String `tfsdk:"certificate_chain"`
	PrivateKey   types.String `tfsdk:"private_key"`
	KeyPassword  types.String `tfsdk:"key_password"`
	// Keyfactor Fields
	CertificateAuthority types.String `tfsdk:"certificate_authority"`
	CertificateTemplate  types.String `tfsdk:"certificate_template"`
	RequestId            types.Int64  `tfsdk:"keyfactor_request_id"`
	Metadata             types.Map    `tfsdk:"metadata"`
	CollectionId         types.Int64  `tfsdk:"collection_id"`
}

type KeyfactorCertificateDeployment struct {
	ID               types.String `tfsdk:"id"`
	CertificateId    types.Int64  `tfsdk:"certificate_id"`
	CertificateAlias types.String `tfsdk:"certificate_alias"`
	StoreId          types.String `tfsdk:"certificate_store_id"`
	KeyPassword      types.String `tfsdk:"key_password"`
}

type CSRCertificate struct {
	ID types.Int64 `tfsdk:"keyfactor_id"`
	// CSR Request Fields
	CSR types.String `tfsdk:"csr"`
	// PFX KfCertificate Fields
	DNSSANs      types.List   `tfsdk:"dns_sans"`
	IPSANs       types.List   `tfsdk:"ip_sans"`
	URISANs      types.List   `tfsdk:"uri_sans"`
	SerialNumber types.String `tfsdk:"serial_number"`
	IssuerDN     types.String `tfsdk:"issuer_dn"`
	Thumbprint   types.String `tfsdk:"thumbprint"`
	PEM          types.String `tfsdk:"certificate_pem"`
	PEMChain     types.String `tfsdk:"certificate_chain"`
	// Keyfactor Fields
	CertificateAuthority types.String `tfsdk:"certificate_authority"`
	CertificateTemplate  types.String `tfsdk:"certificate_template"`
	RequestId            types.Int64  `tfsdk:"keyfactor_request_id"`
	Metadata             types.Map    `tfsdk:"metadata"`
}

type CertificateRequest struct {
	Certificate KeyfactorCertificate `tfsdk:"certificate"`
	CN          types.String         `tfsdk:"subject_common_name"`
	L           types.String         `tfsdk:"subject_locality"`
	O           types.String         `tfsdk:"subject_organization"`
	OU          types.String         `tfsdk:"subject_organizational_unit"`
	ST          types.String         `tfsdk:"subject_state"`
	C           types.String         `tfsdk:"subject_country"`
	Email       types.String         `tfsdk:"subject_email"`
	DNSSANs     types.List           `tfsdk:"dns_subject_alternative_names"`
	IPSANs      types.List           `tfsdk:"ip_subject_alternative_names"`
	URISANs     types.List           `tfsdk:"uri_subject_alternative_names"`
}

type CertificateStore struct {
	ID                    types.String `tfsdk:"id"`
	ContainerID           types.Int64  `tfsdk:"container_id"`
	ContainerName         types.String `tfsdk:"container_name"`
	AgentId               types.String `tfsdk:"agent_id"`
	AgentAssigned         types.Bool   `tfsdk:"agent_assigned"`
	ClientMachine         types.String `tfsdk:"client_machine"`
	StorePath             types.String `tfsdk:"store_path"`
	StoreType             types.String `tfsdk:"store_type"`
	Approved              types.Bool   `tfsdk:"approved"`
	CreateIfMissing       types.Bool   `tfsdk:"create_if_missing"`
	Properties            types.Map    `tfsdk:"properties"`
	Password              types.String `tfsdk:"password"`
	SetNewPasswordAllowed types.Bool   `tfsdk:"set_new_password_allowed"`
	InventorySchedule     types.String `tfsdk:"inventory_schedule"`
}

type CertificateTemplate struct {
	ID                     types.Int64  `tfsdk:"id"`
	CommonName             types.String `tfsdk:"short_name"`
	TemplateName           types.String `tfsdk:"name"`
	OID                    types.String `tfsdk:"oid"`
	KeySize                types.String `tfsdk:"key_size"`
	KeyType                types.String `tfsdk:"key_type"`
	ForestRoot             types.String `tfsdk:"forest_root"`
	FriendlyName           types.String `tfsdk:"friendly_name"`
	KeyRetention           types.String `tfsdk:"key_retention"`
	KeyRetentionDays       types.Int64  `tfsdk:"key_retention_days"`
	KeyArchival            types.Bool   `tfsdk:"key_archival"`
	EnrollmentFields       types.List   `tfsdk:"enrollment_fields"`
	AllowedEnrollmentTypes types.Int64  `tfsdk:"allowed_enrollment_types"`
	TemplateRegexes        types.List   `tfsdk:"template_regexes"`
	AllowedRequesters      types.List   `tfsdk:"allowed_requesters"`
	RFCEnforcement         types.Bool   `tfsdk:"rfc_enforcement"`
	RequiresApproval       types.Bool   `tfsdk:"requires_approval"`
	KeyUsage               types.Int64  `tfsdk:"key_usage"`
	//ExtendedKeyUsage       types.List   `tfsdk:"extended_key_usage"`
}

type CertificateTemplateRoleBinding struct {
	ID            types.String `tfsdk:"id"`
	RoleName      types.String `tfsdk:"role_name"`
	TemplateNames types.List   `tfsdk:"template_short_names"`
}
