package keyfactor

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Security Identity -
type SecurityIdentity struct {
	ID           types.Int64  `tfsdk:"identity_id"`
	AccountName  types.String `tfsdk:"account_name"`
	Roles        types.List   `tfsdk:"roles"`
	IdentityType types.String `tfsdk:"identity_type"`
	Valid        types.Bool   `tfsdk:"valid"`
}

// Role -
type SecurityRole struct {
	ID          types.Int64  `tfsdk:"role_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Permissions types.List   `tfsdk:"permissions"`
}

type KeyfactorCertificate struct {
	ID types.Int64 `tfsdk:"keyfactor_id"`
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
