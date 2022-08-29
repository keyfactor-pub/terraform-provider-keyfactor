package api

// GetSecurityIdentityResponse holds the response data returned by /Security/Identities
type GetSecurityIdentityResponse struct {
	Id           int                       `json:"Id,omitempty"`
	AccountName  string                    `json:"AccountName,omitempty"`
	IdentityType string                    `json:"IdentityType,omitempty"`
	Roles        []SecurityRoleInformation `json:"Roles,omitempty"`
	Valid        bool                      `json:"Valid,omitempty"`
}

// SecurityRoleInformation holds security role information associated with an identity
type SecurityRoleInformation struct {
	Id          int    `json:"Id,omitempty"`
	Name        string `json:"Name,omitempty"`
	Description string `json:"Description,omitempty"`
}

// CreateSecurityIdentityArg holds the request body required to create a new security identity
type CreateSecurityIdentityArg struct {
	AccountName string `json:"AccountName,omitempty"`
}

// CreateSecurityIdentityResponse is returned by the POST call to /Security/Identities
type CreateSecurityIdentityResponse struct {
	Id           int                       `json:"Id,omitempty"`
	AccountName  string                    `json:"AccountName,omitempty"`
	IdentityType string                    `json:"IdentityType,omitempty"`
	Roles        []SecurityRoleInformation `json:"Roles,omitempty"`
	Valid        bool                      `json:"Valid,omitempty"`
}

// GetSecurityRolesResponse holds the response data returned by /Security/Roles
type GetSecurityRolesResponse []struct {
	ID          int                `json:"Id,omitempty"`
	Description string             `json:"Description,omitempty"`
	Enabled     bool               `json:"Enabled"`
	Immutable   bool               `json:"Immutable"`
	Valid       bool               `json:"Valid"`
	Private     bool               `json:"Private"`
	Identities  []SecurityIdentity `json:"Identities,omitempty"`
	Name        string             `json:"Name,omitempty"`
	Permissions []string           `json:"Permissions,omitempty"`
}

type GetSecurityRoleResponse struct {
	Id          int                `json:"Id,omitempty"`
	Name        string             `json:"Name,omitempty"`
	Description string             `json:"Description,omitempty"`
	Identities  []SecurityIdentity `json:"Identities,omitempty"`
	Permissions []string           `json:"Permissions,omitempty"`
}

// SecurityIdentity contains the contains required elements to attach an identity to a role
type SecurityIdentity struct {
	Id           int    `json:"Id,omitempty"`
	AccountName  string `json:"AccountName,omitempty"`
	IdentityType string `json:"IdentityType,omitempty"`
	Sid          string `json:"Sid,omitempty"`
}

// CreateSecurityRoleArg holds the function arguments required for CreateSecurityRole
type CreateSecurityRoleArg struct {
	Name        string                        `json:"Name,omitempty"`
	Description string                        `json:"Description,omitempty"`
	Enabled     *bool                         `json:"Enabled,omitempty"`
	Private     *bool                         `json:"Private,omitempty"`
	Permissions *[]string                     `json:"Permissions,omitempty"` // List of permissions in ["key:value"] format
	Identities  *[]SecurityRoleIdentityConfig `json:"Identities,omitempty"`
}

// SecurityRolePermission holds the permission configuration to create or update a Keyefactor security role. See API
// documentation for specifics on how to configure these fields.
type SecurityRolePermission struct {
	AgentAutoRegistration      *string `json:"AgentAutoRegistration,omitempty"`
	AgentManagement            *string `json:"agent_management,omitempty"`
	API                        *string `json:"api,omitempty"`
	Auditing                   *string `json:"auditing,omitempty"`
	CertificateCollections     *string `json:"certificate_collections,omitempty"`
	CertificateEnrollment      *string `json:"certificate_enrollment,omitempty"`
	CertificateMetadataTypes   *string `json:"certificate_metadata_types,omitempty"`
	CertificateStoreManagement *string `json:"certificate_store_management,omitempty"`
	Certificates               *string `json:"certificates,omitempty"`
	Dashboard                  *string `json:"dashboard,omitempty"`
	MacAutoEnrollManagement    *string `json:"mac_auto_enroll_management,omitempty"`
	AdminPortal                *string `json:"admin_portal,omitempty"`
	Monitoring                 *string `json:"monitoring,omitempty"`
	PkiManagement              *string `json:"pki_management,omitempty"`
	Reports                    *string `json:"reports,omitempty"`
	SecuritySettings           *string `json:"security_settings,omitempty"`
	SSH                        *string `json:"ssh,omitempty"`
	SslManagement              *string `json:"ssl_management,omitempty"`
	SystemSettings             *string `json:"system_settings,omitempty"`
	WorkflowManagement         *string `json:"workflow_management,omitempty"`
}

// SecurityRoleIdentityConfig holds configuration data defining which security identities are attached to a given
// security role.
type SecurityRoleIdentityConfig struct {
	AccountName string
	SID         *string
}

// CreateSecurityRoleResponse holds response elements returned by
type CreateSecurityRoleResponse struct {
	Id          int                           `json:"Id,omitempty"`
	Name        string                        `json:"Name,omitempty"`
	Description string                        `json:"Description,omitempty"`
	Enabled     *bool                         `json:"Enabled,omitempty"`
	Immutable   bool                          `json:"Immutable,omitempty"`
	Private     *bool                         `json:"Private,omitempty"`
	Permissions *[]string                     `json:"Permissions,omitempty"` // List of permissions in ["key:value"] format
	Identities  *[]SecurityRoleIdentityConfig `json:"Identities,omitempty"`
}

// UpdateSecurityRoleArg holds the function arguments used for calling the UpdateSecurityRole method.
type UpdateSecurityRoleArg struct {
	Id int `json:"Id,omitempty"`
	CreateSecurityRoleArg
}

// UpdateSecurityRoleResponse holds the response elements returned by the UpdateSecurityRole method
type UpdateSecurityRoleResponse struct {
	CreateSecurityRoleResponse
}
