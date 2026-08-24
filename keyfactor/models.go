package keyfactor

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CommandAgent represents an agent in the Keyfactor system.
//
// NOTE: TfId (tfsdk:"id") is a read-only mirror of AgentId, required by the SDKv2 test harness.
// Do NOT read from or write to TfId directly; it is populated automatically via syncTfId().
type CommandAgent struct {
	TfId                        types.String `tfsdk:"id"`                            // Read-only mirror of AgentId for test framework.
	AgentId                     types.String `tfsdk:"agent_id"`                      // Unique identifier for the agent.
	AgentIdentifier             types.String `tfsdk:"agent_identifier"`              // Identifier for the agent in Keyfactor.
	ClientMachine               types.String `tfsdk:"client_machine"`                // Machine name where the agent is running.
	Username                    types.String `tfsdk:"username"`                      // Username associated with the agent.
	AgentPlatform               types.Int64  `tfsdk:"agent_platform"`                // Platform type of the agent (e.g., Windows, Linux).
	Status                      types.Int64  `tfsdk:"status"`                        // Current status of the agent.
	Version                     types.String `tfsdk:"version"`                       // Version of the agent.
	LastSeen                    types.String `tfsdk:"last_seen"`                     // Timestamp of the agent's last activity.
	Capabilities                types.List   `tfsdk:"capabilities"`                  // Capabilities supported by the agent.
	Blueprint                   types.String `tfsdk:"blueprint"`                     // Associated blueprint for the agent.
	Thumbprint                  types.String `tfsdk:"thumbprint"`                    // Certificate thumbprint used by the agent.
	LegacyThumbprint            types.String `tfsdk:"legacy_thumbprint"`             // Legacy certificate thumbprint used by the agent.
	AuthCertificateReenrollment types.String `tfsdk:"auth_certificate_reenrollment"` // Flag indicating if reenrollment is required.
	LastThumbprintUsed          types.String `tfsdk:"last_thumbprint_used"`          // Last thumbprint used by the agent for authentication.
	LastErrorCode               types.Int64  `tfsdk:"last_error_code"`               // Last error code reported by the agent.
	LastErrorMessage            types.String `tfsdk:"last_error_message"`            // Last error message reported by the agent.
}

func (a *CommandAgent) syncTfId() { a.TfId = a.AgentId }

// SecurityIdentity represents an identity with security roles in Keyfactor.
type SecurityIdentity struct {
	ID           types.Int64  `tfsdk:"id"`            // Unique ID of the security identity.
	AccountName  types.String `tfsdk:"account_name"`  // Account name associated with the identity.
	Roles        types.List   `tfsdk:"roles"`         // List of roles assigned to this identity.
	IdentityType types.String `tfsdk:"identity_type"` // Type of the identity (e.g., user, application).
	Valid        types.Bool   `tfsdk:"valid"`         // Indicates if the identity is valid.
}

// DEPRECATED: SecurityRole represents a security role in Keyfactor.
// This struct is deprecated and should be used for backward compatibility only.
// It is recommended to use the `OAuthSecurityClaim` struct.
type SecurityRole struct {
	ID          types.Int64  `tfsdk:"id"`          // Unique ID of the security role.
	Name        types.String `tfsdk:"name"`        // Name of the security role.
	Description types.String `tfsdk:"description"` // Description of the role.
	Permissions types.List   `tfsdk:"permissions"` // List of permissions assigned to the role.
}

var OAuthSecurityClaimAuthenticationProviderType = map[string]attr.Type{
	"id":                    types.StringType,
	"authentication_scheme": types.StringType,
	"display_name":          types.StringType,
}

var OAuthSecurityClaimType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"id":          types.Int64Type,
		"claim_type":  types.StringType,
		"claim_value": types.StringType,
		"description": types.StringType,
		"provider": types.ObjectType{
			AttrTypes: OAuthSecurityClaimAuthenticationProviderType,
		},
	},
}

type PermissionSet struct {
	ID          types.String `tfsdk:"id"`          // Unique ID for the permission set.
	Name        types.String `tfsdk:"name"`        // Name of the permission set.
	Permissions types.List   `tfsdk:"permissions"` // List of permissions associated with the permission set.
}

// OAuthSecurityClaim represents an OAuth security claim in Keyfactor.
type OAuthSecurityClaim struct {
	ID                           types.Int64  `tfsdk:"id"`                             // Unique ID of the OAuth security claim.
	Description                  types.String `tfsdk:"description"`                    // Description of the OAuth security claim.
	ClaimType                    types.String `tfsdk:"claim_type"`                     // Type of the OAuth security claim.
	ClaimValue                   types.String `tfsdk:"claim_value"`                    // Value of the OAuth security claim.
	Provider                     types.Object `tfsdk:"provider"`                       // Authentication Provider of the OAuth security claim.
	ProviderAuthenticationScheme types.String `tfsdk:"provider_authentication_scheme"` // Authentication Provider of the OAuth security claim.
}

// OAuthSecurityRole represents an OAuth security role in Keyfactor.
type OAuthSecurityRole struct {
	ID              types.Int64  `tfsdk:"id"`                // Unique ID of the OAuth security role.
	Name            types.String `tfsdk:"name"`              // Name of the OAuth security role.
	Description     types.String `tfsdk:"description"`       // Description of the OAuth security role.
	EmailAddress    types.String `tfsdk:"email_address"`     // Email address associated with the OAuth security role.
	Immutable       types.Bool   `tfsdk:"immutable"`         // Indicates if the OAuth security role is immutable.
	Permissions     types.Set    `tfsdk:"permissions"`       // List of permissions assigned to the OAuth security role.
	PermissionSetId types.String `tfsdk:"permission_set_id"` // Permission Set ID associated with the OAuth security role.
}

// OAuthSecurityRoleClaimAssociation represents an association between an OAuth security role and an OAuth security claim.
type OAuthSecurityRoleClaimAssociation struct {
	ID      types.String `tfsdk:"id"`       // Unique ID of the association between the OAuth security role and the OAuth security claim. This is computed when the role claim association is created.
	RoleID  types.Int64  `tfsdk:"role_id"`  // ID of the OAuth security role.
	ClaimID types.Int64  `tfsdk:"claim_id"` // ID of the OAuth security claim to be associated with the OAuth security role.
}

// CommandCertificate represents a certificate entity in Keyfactor.
//
// NOTE: This struct has two ID-related fields due to a Terraform testing framework requirement:
//   - ID  (tfsdk:"identifier") — The actual Keyfactor certificate identifier. Used throughout provider code.
//   - TfId (tfsdk:"id")        — Read-only mirror of ID, required by the SDKv2 test harness.
//     Do NOT read from or write to TfId directly; it is populated automatically via syncTfId().
type CommandCertificate struct {
	TfId types.String `tfsdk:"id"`         // Read-only mirror of ID for Terraform test framework. Use syncTfId() only.
	ID   types.String `tfsdk:"identifier"` // Unique identifier of the certificate.

	// CSR Request Fields
	CSR types.String `tfsdk:"csr"` // Certificate Signing Request (CSR) content.

	// PFX Fields
	FriendlyName        types.String `tfsdk:"friendly_name"`           // Friendly name for the certificate in Keyfactor.
	UseCNAsFriendlyName types.Bool   `tfsdk:"use_cn_as_friendly_name"` // Indicates whether Common Name should be used as the friendly name.

	// Subject Fields
	CommonName         types.String `tfsdk:"common_name"`         // Common Name (CN) field of the certificate.
	Locality           types.String `tfsdk:"locality"`            // Locality (L) field of the certificate.
	State              types.String `tfsdk:"state"`               // State (ST) field of the certificate.
	Country            types.String `tfsdk:"country"`             // Country (C) field of the certificate.
	Organization       types.String `tfsdk:"organization"`        // Organization (O) field of the certificate.
	OrganizationalUnit types.String `tfsdk:"organizational_unit"` // Organizational Unit (OU) field of the certificate.

	// SAN Fields
	DNSSANs types.List `tfsdk:"dns_sans"` // List of DNS Subject Alternative Names (SAN).
	IPSANs  types.List `tfsdk:"ip_sans"`  // List of IP Address Subject Alternative Names (SAN).
	URISANs types.List `tfsdk:"uri_sans"` // List of URI Subject Alternative Names (SAN).

	// Certificate Identity Fields
	SerialNumber types.String `tfsdk:"serial_number"` // Serial number of the certificate.
	IssuerDN     types.String `tfsdk:"issuer_dn"`     // Issuer Distinguished Name (DN) of the certificate.
	Thumbprint   types.String `tfsdk:"thumbprint"`    // Thumbprint of the certificate.

	// Certificate Data Fields
	PEM       types.String `tfsdk:"certificate_pem"`   // Certificate data in PEM format.
	PEMCACert types.String `tfsdk:"ca_certificate"`    // CA Certificate in PEM format.
	PEMChain  types.String `tfsdk:"certificate_chain"` // Certificate chain in PEM format.
	PFX       types.String `tfsdk:"pfx"`               // Certificate data in PFX format (Base64 encoded).
	JKS       types.String `tfsdk:"jks"`               // Certificate data in JKS format (Base64 encoded).
	Zip       types.String `tfsdk:"zip"`               // Certificate data in ZIP format (Base64 encoded).

	PrivateKey         types.String `tfsdk:"private_key"`         // PrivateKey in PEM format.
	KeyPassword        types.String `tfsdk:"key_password"`        // KeyPassword for the private key.
	EnrollmentPassword types.String `tfsdk:"enrollment_password"` // EnrollmentPassword used during certificate issuance.

	// Keyfactor Fields
	CertificateAuthority types.String                `tfsdk:"certificate_authority"` // CertificateAuthority defines the CA name used for certificate issuance in Keyfactor Command
	CertificateTemplate  types.String                `tfsdk:"certificate_template"`  // CertificateTemplate defines the template to be used for certificate issuance in Keyfactor Command
	RequestId            types.Int64                 `tfsdk:"command_request_id"`    // RequestId represents the unique identifier for the certificate command request in Keyfactor Command.
	CertificateId        types.Int64                 `tfsdk:"certificate_id"`        // CertificateId represents the unique identifier for the certificate in Keyfactor Command
	Metadata             types.Map                   `tfsdk:"metadata"`              // Metadata associated with the certificate.
	CollectionId         types.Int64                 `tfsdk:"collection_id"`         // CollectionId represents the ID for the Keyfactor Command collection associated with the certificate.
	ExpiryWarningDays    types.Int64                 `tfsdk:"expiry_warn_days"`      // ExpiryWarningDays specifies the number of days before expiration to trigger a warning.
	IsExpired            types.Bool                  `tfsdk:"is_expired"`            // IsExpired indicates whether the certificate is expired.
	IsRevoked            types.Bool                  `tfsdk:"is_revoked"`            // IsRevoked indicates whether the certificate has been revoked.
	IsPendingRevocation  types.Bool                  `tfsdk:"is_pending_revocation"` // IsPendingRevocation indicates whether the certificate is waiting to be revoked.
	RenewalConfig        *CertificateAutoRenewConfig `tfsdk:"renewal_config"`

	// v11.0.0+ Fields
	CertificateFormat types.String `tfsdk:"certificate_format"` // CertificateFormat defines the format of the certificate. Valid values are "PFX", "PEM", "JKS", "ZIP".

	// v12.3.0+ Fields
	OwnerRoleName types.String `tfsdk:"owner_role_name"` // OwnerRoleName either the internal ID or name of the role that will own the certificate.

	// v25.1.0+ Fields
	EnrollmentPattern types.String `tfsdk:"certificate_enrollment_pattern"` // EnrollmentPattern is either the internal ID
	// or the name of the enrollment pattern to be used for certificate issuance.

	NotBefore         types.String `tfsdk:"not_before"`                // NotBefore represents the start date and time from which the certificate is valid.
	NotAfter          types.String `tfsdk:"not_after"`                 // NotAfter represents the end date and time after which the certificate is no longer valid.
	RevocationEffDate types.String `tfsdk:"revocation_effective_date"` // RevocationEffDate represents the date and time when the revocation of the certificate becomes effective.
	RevokeOnDestroy   types.Bool   `tfsdk:"revoke_on_destroy"`         // RevokeOnDestroy indicates whether the certificate should be revoked when the resource is destroyed.

	// PFX key generation options
	KeyType types.String `tfsdk:"key_type"` // KeyType for PFX enrollment: RSA, ECC, Ed25519, Ed448.
	KeySize types.Int64  `tfsdk:"key_size"` // KeySize in bits for PFX enrollment (e.g. 2048/4096 for RSA; 256/384/521 for ECC).
	Curve   types.String `tfsdk:"curve"`    // Curve name for ECC PFX enrollment (e.g. P-256, P-384, P-521).
}

// DataCommandCertificate represents a certificate data source entity in Keyfactor.
// See CommandCertificate for notes on TfId vs ID.
type DataCommandCertificate struct {
	TfId types.String `tfsdk:"id"`         // Read-only mirror of ID for Terraform test framework. Use syncTfId() only.
	ID   types.String `tfsdk:"identifier"` // Unique identifier of the certificate.

	// CSR Request Fields
	CSR types.String `tfsdk:"csr"` // Certificate Signing Request (CSR) content.

	// PFX Fields
	FriendlyName        types.String `tfsdk:"friendly_name"`           // Friendly name for the certificate in Keyfactor.
	UseCNAsFriendlyName types.Bool   `tfsdk:"use_cn_as_friendly_name"` // Indicates whether Common Name should be used as the friendly name.

	// Subject Fields
	CommonName         types.String `tfsdk:"common_name"`         // Common Name (CN) field of the certificate.
	Locality           types.String `tfsdk:"locality"`            // Locality (L) field of the certificate.
	State              types.String `tfsdk:"state"`               // State (ST) field of the certificate.
	Country            types.String `tfsdk:"country"`             // Country (C) field of the certificate.
	Organization       types.String `tfsdk:"organization"`        // Organization (O) field of the certificate.
	OrganizationalUnit types.String `tfsdk:"organizational_unit"` // Organizational Unit (OU) field of the certificate.

	// SAN Fields
	DNSSANs types.List `tfsdk:"dns_sans"` // List of DNS Subject Alternative Names (SAN).
	IPSANs  types.List `tfsdk:"ip_sans"`  // List of IP Address Subject Alternative Names (SAN).
	URISANs types.List `tfsdk:"uri_sans"` // List of URI Subject Alternative Names (SAN).

	// Certificate Identity Fields
	SerialNumber types.String `tfsdk:"serial_number"` // Serial number of the certificate.
	IssuerDN     types.String `tfsdk:"issuer_dn"`     // Issuer Distinguished Name (DN) of the certificate.
	Thumbprint   types.String `tfsdk:"thumbprint"`    // Thumbprint of the certificate.

	// Certificate Data Fields
	PEM       types.String `tfsdk:"certificate_pem"`   // Certificate data in PEM format.
	PEMCACert types.String `tfsdk:"ca_certificate"`    // CA Certificate in PEM format.
	PEMChain  types.String `tfsdk:"certificate_chain"` // Certificate chain in PEM format.
	PFX       types.String `tfsdk:"pfx"`               // Certificate data in PFX format (Base64 encoded).
	JKS       types.String `tfsdk:"jks"`               // Certificate data in JKS format (Base64 encoded).
	Zip       types.String `tfsdk:"zip"`               // Certificate data in ZIP format (Base64 encoded).

	PrivateKey         types.String `tfsdk:"private_key"`         // PrivateKey in PEM format.
	KeyPassword        types.String `tfsdk:"key_password"`        // KeyPassword for the private key.
	EnrollmentPassword types.String `tfsdk:"enrollment_password"` // EnrollmentPassword used during certificate issuance.

	// Keyfactor Fields
	CertificateAuthority types.String `tfsdk:"certificate_authority"` // CertificateAuthority defines the CA name used for certificate issuance in Keyfactor Command
	CertificateTemplate  types.String `tfsdk:"certificate_template"`  // CertificateTemplate defines the template to be used for certificate issuance in Keyfactor Command
	RequestId            types.Int64  `tfsdk:"command_request_id"`    // RequestId represents the unique identifier for the certificate command request in Keyfactor Command.
	CertificateId        types.Int64  `tfsdk:"certificate_id"`        // CertificateId represents the unique identifier for the certificate in Keyfactor Command
	Metadata             types.Map    `tfsdk:"metadata"`              // Metadata associated with the certificate.
	CollectionId         types.Int64  `tfsdk:"collection_id"`         // CollectionId represents the ID for the Keyfactor Command collection associated with the certificate.
	ExpiryWarningDays    types.Int64  `tfsdk:"expiry_warn_days"`      // ExpiryWarningDays specifies the number of days before expiration to trigger a warning.
	IsExpired            types.Bool   `tfsdk:"is_expired"`            // IsExpired indicates whether the certificate is expired.
	IsRevoked            types.Bool   `tfsdk:"is_revoked"`            // IsRevoked indicates whether the certificate has been revoked.
	IsPendingRevocation  types.Bool   `tfsdk:"is_pending_revocation"` // IsPendingRevocation indicates whether the certificate is waiting to be revoked.
	//RenewalConfig        *CertificateAutoRenewConfig `tfsdk:"renewal_config"`

	// v11.0.0+ Fields
	CertificateFormat types.String `tfsdk:"certificate_format"` // CertificateFormat defines the format of the certificate. Valid values are "PFX", "PEM", "JKS", "ZIP".

	// v12.3.0+ Fields
	OwnerRoleName types.String `tfsdk:"owner_role_name"` // OwnerRoleName either the internal ID or name of the role that will own the certificate.

	// v25.1.0+ Fields
	EnrollmentPattern types.String `tfsdk:"certificate_enrollment_pattern"` // EnrollmentPattern is either the internal ID
	// or the name of the enrollment pattern to be used for certificate issuance.

	NotBefore         types.String `tfsdk:"not_before"`                // NotBefore represents the start date and time from which the certificate is valid.
	NotAfter          types.String `tfsdk:"not_after"`                 // NotAfter represents the end date and time after which the certificate is no longer valid.
	RevocationEffDate types.String `tfsdk:"revocation_effective_date"` // RevocationEffDate represents the date and time when the revocation of the certificate becomes effective.

	// Key info (read from issued certificate)
	KeyType types.String `tfsdk:"key_type"` // KeyType of the issued certificate (e.g. RSA, ECC, Ed25519).
	KeySize types.Int64  `tfsdk:"key_size"` // KeySize in bits of the issued certificate.
	Curve   types.String `tfsdk:"curve"`    // Curve name for ECC certificates.
}

// syncTfId copies the ID (identifier) value to the TfId (id) field.
// Must be called before every State.Set() on a CommandCertificate.
func (c *CommandCertificate) syncTfId() { c.TfId = c.ID }

// syncTfId copies the ID (identifier) value to the TfId (id) field.
// Must be called before every State.Set() on a DataCommandCertificate.
func (c *DataCommandCertificate) syncTfId() { c.TfId = c.ID }

type CertificateAutoRenewConfig struct {
	ForceRenewal types.Bool  `tfsdk:"force_renewal"` // ForceRenewal indicates if the certificate should be forcefully renewed, regardless of its current state.
	RenewDays    types.Int64 `tfsdk:"renew_days"`    // RenewDays specifies the number of days before expiration
	// to attempt automatic renewal of the certificate. If not set, automatic renewal is disabled
	RenewEligible types.Bool `tfsdk:"renew_eligible"` // RenewEligible indicates whether the certificate is
	// eligible for renewal, based on RenewDays
	RevokeOnRenew types.Bool `tfsdk:"revoke_on_renew"` // RevokeOnRenew indicates whether the certificate should
	// be revoked upon renewal. Default is `false`
}

// CommandCertificateDeployment represents a deployment of a certificate to a store.
type CommandCertificateDeployment struct {
	ID               types.String `tfsdk:"id"`                   // ID represents the unique identifier for the certificate deployment resource.
	CertificateId    types.Int64  `tfsdk:"certificate_id"`       // CertificateId represents the unique identifier for the certificate being deployed.
	CertificateAlias types.String `tfsdk:"certificate_alias"`    // CertificateAlias specifies the alias for the certificate being deployed in the store.
	StoreId          types.String `tfsdk:"certificate_store_id"` // ID of the store where the certificate is deployed.
	KeyPassword      types.String `tfsdk:"key_password"`         // KeyPassword represents the password for the private key associated with the certificate being deployed.
	JobParameters    types.Map    `tfsdk:"job_parameters"`       // JobParameters represents additional parameters for the certificate deployment job as a map of key-value pairs.
	Overwrite        types.Bool   `tfsdk:"overwrite"`            // Overwrite specifies whether an existing certificate should be overwritten during deployment.
	Redeploy         types.Bool   `tfsdk:"redeploy"`             // Redeploy specifies whether a certificate should be redeployed to the store during the deployment process.
	SkipRemoval      types.Bool   `tfsdk:"skip_removal"`         // SkipRemoval specifies whether the removal of the certificate from the store should be skipped during undeployment.
}

// CSRCertificate represents a certificate provisioned via a CSR in Keyfactor.
type CSRCertificate struct {
	ID           types.Int64  `tfsdk:"keyfactor_id"`  // Unique ID of the CSR certificate.
	CSR          types.String `tfsdk:"csr"`           // Certificate Signing Request (CSR) content.
	DNSSANs      types.List   `tfsdk:"dns_sans"`      // List of DNS Subject Alternative Names (SAN).
	IPSANs       types.List   `tfsdk:"ip_sans"`       // List of IP Address Subject Alternative Names (SAN).
	URISANs      types.List   `tfsdk:"uri_sans"`      // List of URI Subject Alternative Names (SAN).
	SerialNumber types.String `tfsdk:"serial_number"` // Serial number of the certificate.
}

type CertificateRequest struct {
	Certificate CommandCertificate `tfsdk:"certificate"`
	CN          types.String       `tfsdk:"subject_common_name"`
	L           types.String       `tfsdk:"subject_locality"`
	O           types.String       `tfsdk:"subject_organization"`
	OU          types.String       `tfsdk:"subject_organizational_unit"`
	ST          types.String       `tfsdk:"subject_state"`
	C           types.String       `tfsdk:"subject_country"`
	Email       types.String       `tfsdk:"subject_email"`
	DNSSANs     types.List         `tfsdk:"dns_subject_alternative_names"`
	IPSANs      types.List         `tfsdk:"ip_subject_alternative_names"`
	URISANs     types.List         `tfsdk:"uri_subject_alternative_names"`
}

type CertificateStore struct {
	ID                    types.String `tfsdk:"id"`
	ContainerID           types.Int64  `tfsdk:"container_id"`
	ContainerName         types.String `tfsdk:"container_name"`
	ApplicationName       types.String `tfsdk:"application_name"`
	AgentId               types.String `tfsdk:"agent_id"`
	AgentIdentifier       types.String `tfsdk:"agent_identifier"`
	AgentAssigned         types.Bool   `tfsdk:"agent_assigned"`
	ClientMachine         types.String `tfsdk:"client_machine"`
	DisplayName           types.String `tfsdk:"display_name"`
	StorePath             types.String `tfsdk:"store_path"`
	StoreType             types.String `tfsdk:"store_type"`
	Approved              types.Bool   `tfsdk:"approved"`
	CreateIfMissing       types.Bool   `tfsdk:"create_if_missing"`
	Properties            types.Map    `tfsdk:"properties"`
	SetNewPasswordAllowed types.Bool   `tfsdk:"set_new_password_allowed"`
	ServerUsername        types.String `tfsdk:"server_username"`
	ServerPassword        types.String `tfsdk:"server_password"`
	ServerUseSsl          types.Bool   `tfsdk:"server_use_ssl"`
	StorePassword         types.String `tfsdk:"store_password"`
	InventorySchedule     types.String `tfsdk:"inventory_schedule"`
}

// effectiveContainerName returns the resolved container/application name from the
// CertificateStore model. It prefers application_name (v25+) over container_name.
// If both are set, application_name wins. Returns ("", true) when neither is set.
func (s *CertificateStore) effectiveContainerName() (string, bool) {
	if !s.ApplicationName.IsNull() && s.ApplicationName.Value != "" {
		return s.ApplicationName.Value, false
	}
	if !s.ContainerName.IsNull() && s.ContainerName.Value != "" {
		return s.ContainerName.Value, false
	}
	return "", true
}

// syncApplicationAndContainerName ensures both application_name and container_name
// reflect the same server-side value. Call this when building state from API responses.
func (s *CertificateStore) syncApplicationAndContainerName(serverValue string) {
	isNull := isNullString(serverValue)
	s.ContainerName = types.String{Value: serverValue, Null: isNull}
	s.ApplicationName = types.String{Value: serverValue, Null: isNull}
}

type CertificateStoreCredential struct {
	ServerUsername struct {
		Value struct {
			SecretValue string `json:"SecretValue"`
		} `json:"value"`
	} `json:"ServerUsername"`
	ServerPassword struct {
		Value struct {
			SecretValue string `json:"SecretValue"`
		} `json:"value"`
	} `json:"ServerPassword"`
	ServerUseSsl struct {
		Value string `json:"value"`
	} `json:"ServerUseSsl"`
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

type CertificateEnrollmentPattern struct {
	Identifier             types.String                       `tfsdk:"identifier"`
	ID                     types.Int64                        `tfsdk:"id"`
	Name                   types.String                       `tfsdk:"name"`
	Description            types.String                       `tfsdk:"description"`
	Template               *EnrollmentPatternTemplate         `tfsdk:"template"`
	TemplateDefault        types.Bool                         `tfsdk:"template_default"`
	UseADPermissions       types.Bool                         `tfsdk:"use_ad_permissions"`
	AssociatedRoles        *[]EnrollmentPatternAssociatedRole `tfsdk:"associated_roles"`
	CertificateAuthorities *[]EnrollmentPatternCA             `tfsdk:"certificate_authorities"`
	AllowedEnrollmentTypes types.Int64                        `tfsdk:"allowed_enrollment_types"`
	Regexes                *[]EnrollmentPatternRegexes        `tfsdk:"regexes"`
	MetadataFields         *[]EnrollmentPatternMetadataField  `tfsdk:"metadata_fields"`
	RestrictCAs            types.Bool                         `tfsdk:"restrict_cas"`
	Policies               *EnrollmentPatternPolicyResponse   `tfsdk:"policies"`
	Defaults               *[]EnrollmentPatternDefault        `tfsdk:"defaults"`
	EnrollmentFields       *[]EnrollmentPatternField          `tfsdk:"enrollment_fields"`
}

type EnrollmentPatternTemplate struct {
	Id                  types.Int64  `tfsdk:"id"`
	TemplateName        types.String `tfsdk:"template_name"`
	CommonName          types.String `tfsdk:"common_name"`
	ConfigurationTenant types.String `tfsdk:"configuration_tenant"`
	RequiresApproval    types.Bool   `tfsdk:"requires_approval"`
	FriendlyName        types.String `tfsdk:"friendly_name"`
}

type EnrollmentPatternAssociatedRole struct {
	Id   types.Int64  `tfsdk:"id"`   // Role ID
	Name types.String `tfsdk:"name"` // Role Name
}

type EnrollmentPatternCA struct {
	Id                  types.Int64  `tfsdk:"id"`
	LogicalName         types.String `tfsdk:"logical_name"`
	HostName            types.String `tfsdk:"host_name"`
	ConfigurationTenant types.String `tfsdk:"configuration_tenant"`
}

type EnrollmentPatternRegexes struct {
	SubjectPart   types.String `tfsdk:"subject_part"`
	Regex         types.String `tfsdk:"regex"`
	Error         types.String `tfsdk:"error"`
	CaseSensitive types.Bool   `tfsdk:"case_sensitive"`
}

type EnrollmentPatternMetadataField struct {
	MetadataId    types.Int64  `tfsdk:"metadata_id"`
	DefaultValue  types.String `tfsdk:"default_value"`
	Validation    types.String `tfsdk:"validation"`
	Enrollment    types.Int64  `tfsdk:"enrollment"`
	Message       types.String `tfsdk:"message"`
	CaseSensitive types.Bool   `tfsdk:"case_sensitive"`
}

type EnrollmentPatternPolicyResponse struct {
	AllowKeyReuse                   types.Bool                                  `tfsdk:"allow_key_reuse"`
	AllowWildcards                  types.Bool                                  `tfsdk:"allow_wildcards"`
	RFCEnforcement                  types.Bool                                  `tfsdk:"rfc_enforcement"`
	CertificateOwnerRole            types.Int64                                 `tfsdk:"certificate_owner_role"` // enums 0-3
	DefaultCertificateOwnerRoleId   types.Int64                                 `tfsdk:"default_certificate_owner_role_id"`
	DefaultCertificateOwnerRoleName types.String                                `tfsdk:"default_certificate_owner_role_name"`
	DefaultCertificateOwnerOverride types.Bool                                  `tfsdk:"default_certificate_owner_override"`
	PrimaryKeyAlgorithms            []EnrollmentPatternsAlgorithmsAlgorithmData `tfsdk:"primary_key_algorithms"`
	AlternativeKeyAlgorithms        []EnrollmentPatternsAlgorithmsAlgorithmData `tfsdk:"alternative_key_algorithms"`
}

type EnrollmentPatternsAlgorithmsAlgorithmData struct {
	Name       types.String `tfsdk:"name"`
	BitLengths types.List   `tfsdk:"bit_lengths"`
	CurveName  types.List   `tfsdk:"curves"`
}

type EnrollmentPatternDefault struct {
	SubjectPart types.String `tfsdk:"subject_part"`
	Value       types.String `tfsdk:"value"`
}

type EnrollmentPatternField struct {
	Id             types.Int64  `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	DefaultValue   types.String `tfsdk:"default_value"`
	Validation     types.String `tfsdk:"validation"`
	Enrollment     types.Int64  `tfsdk:"enrollment"`
	Message        types.String `tfsdk:"message"`
	Options        types.List   `tfsdk:"options"`
	DependsOn      types.String `tfsdk:"depends_on"`
	DependsOnValue types.String `tfsdk:"depends_on_value"`
	DataType       types.Int64  `tfsdk:"data_type"`
	Hint           types.String `tfsdk:"hint"`
}
