package keyfactor

// CreateStoreFctArgs holds the function arguments used for calling the CreateStore method.
type CreateStoreFctArgs struct {
	ContainerId             *int    `json:"ContainerId,omitempty"`
	ClientMachine           string  `json:"ClientMachine"`
	StorePath               string  `json:"StorePath"`
	CertStoreInventoryJobId *string `json:"CertStoreInventoryJobId,omitempty"`
	CertStoreType           int     `json:"CertStoreType"`
	Approved                *bool   `json:"Approved,omitempty"`
	CreateIfMissing         *bool   `json:"CreateIfMissing,omitempty"`
	// String JSON name-value pairs; this field is not recommended. Instead, please use Properties. This field is
	// automatically populated by the CreateStore method. However, if configured, this field will be used.
	PropertiesString string `json:"Properties,omitempty"`
	// Mapped name-value pair field used to configure properties.
	Properties            map[string]string    `json:"-"`
	AgentId               string               `json:"AgentId"`
	AgentAssigned         *bool                `json:"AgentAssigned,omitempty"`
	ContainerName         *string              `json:"ContainerName,omitempty"`
	InventorySchedule     *InventorySchedule   `json:"InventorySchedule,omitempty"`
	ReEnrollmentStatus    *ReEnrollmnentConfig `json:"ReEnrollmentStatus,omitempty"`
	SetNewPasswordAllowed *bool                `json:"SetNewPasswordAllowed,omitempty"`
	Password              *StorePasswordConfig `json:"Password,omitempty"`
}

// UpdateStoreFctArgs holds the function arguments used for calling the UpdateStore method.
type UpdateStoreFctArgs struct {
	Id string `json:"Id,omitempty"`
	CreateStoreFctArgs
}

// InventorySchedule holds configuration data for creating an inventory schedule for a certificate store in Keyfactor
type InventorySchedule struct {
	Immediate   *bool              `json:"Immediate,omitempty"`
	Interval    *InventoryInterval `json:"Interval,omitempty"`
	Daily       *InventoryDaily    `json:"Daily,omitempty"`
	ExactlyOnce *InventoryOnce     `json:"ExactlyOnce,omitempty"`
}

// InventoryInterval specifies that the inventory should happen at a given interval in minutes
type InventoryInterval struct {
	Minutes int `json:"Minutes"`
}

// InventoryDaily specifies that the inventory should happen at a given time in the day, daily
type InventoryDaily struct {
	Time string `json:"Time"`
}

// InventoryOnce specifies that the inventory should happen once, at a given time
type InventoryOnce struct {
	Time string `json:"Time"`
}

// ReEnrollmnentConfig configures the re-enrollment job for a created certificate.
type ReEnrollmnentConfig struct {
	Data               bool   `json:"Data"`
	AgentId            string `json:"AgentId"`
	Message            string `json:"Message"`
	JobProperties      string `json:"JobProperties"`
	CustomAliasAllowed int    `json:"CustomAliasAllowed"`
}

// StorePasswordConfig configures the password field for a new certificate store.
type StorePasswordConfig struct {
	Value          *string `json:"Value"`
	SecretTypeGuid *string `json:"SecretTypeGuid,omitempty"`
	InstanceId     *string `json:"InstanceId,omitempty"`
} // ProviderTypeParameterValues - Not yet implemented
// ProviderTypeParameterValues ProviderTypeParams - Not implemented

/* Future non-critical functionality */

type ProviderTypeParams struct {
	Id           string
	Value        string
	InstanceId   string
	InstanceGuid string
	Provider     ProviderParams
}

type ProviderParams struct {
	Id           int
	Name         string
	Area         int
	ProviderType ProviderType
}

type ProviderType struct {
	Id   string
	Name string
}

// CertStoreTypeResponse contains the response elements returned from the GetCertStoreType method.
type CertStoreTypeResponse struct {
	Name                string `json:"Name"`
	ShortName           string `json:"ShortName"`
	Capability          string `json:"Capability"`
	StoreType           int    `json:"StoreType"`
	ImportType          int    `json:"ImportType"`
	LocalStore          bool   `json:"LocalStore"`
	SupportedOperations struct {
		Add        bool `json:"Add"`
		Create     bool `json:"Create"`
		Discovery  bool `json:"Discovery"`
		Enrollment bool `json:"Enrollment"`
		Remove     bool `json:"Remove"`
	} `json:"SupportedOperations"`
	Properties      []PropertyDefinition `json:"Properties"`
	PasswordOptions struct {
		EntrySupported bool   `json:"EntrySupported"`
		StoreRequired  bool   `json:"StoreRequired"`
		Style          string `json:"Style"`
	} `json:"PasswordOptions"`
	StorePathValue     []string `json:"store_path_value"`
	PrivateKeyAllowed  string   `json:"private_key_allowed"`
	JobProperties      []string `json:"job_properties"`
	ServerRequired     bool     `json:"ServerRequired"`
	PowerShell         bool     `json:"PowerShell"`
	BlueprintAllowed   bool     `json:"BlueprintAllowed"`
	CustomAliasAllowed string   `json:"CustomAliasAllowed"`
	ServerRegistration int      `json:"ServerRegistration"`
	InventoryEndpoint  string   `json:"InventoryEndpoint"`
	InventoryJobType   string   `json:"InventoryJobType"`
	ManagementJobType  string   `json:"ManagementJobType"`
	DiscoveryJobType   string   `json:"DiscoveryJobType"`
	EnrollmentJobType  string   `json:"EnrollmentJobType"`
}

// GetStoreByIDResp contains the response elements returned from the GetCertificateStoreByID method.
type GetStoreByIDResp struct {
	Id                      string              `json:"Id,omitempty"`
	ContainerId             int                 `json:"ContainerId,omitempty"`
	ClientMachine           string              `json:"ClientMachine,omitempty"`
	StorePath               string              `json:"StorePath,omitempty"`
	CertStoreInventoryJobId string              `json:"CertStoreInventoryJobId,omitempty"`
	CertStoreType           int                 `json:"CertStoreType,omitempty"`
	Approved                bool                `json:"Approved,omitempty"`
	CreateIfMissing         bool                `json:"CreateIfMissing,omitempty"`
	PropertiesString        string              `json:"Properties,omitempty"`
	Properties              map[string]string   `json:"-"`
	AgentId                 string              `json:"AgentId,omitempty"`
	AgentAssigned           bool                `json:"AgentAssigned,omitempty"`
	ContainerName           string              `json:"ContainerName,omitempty"`
	InventorySchedule       InventorySchedule   `json:"InventorySchedule"`
	ReenrollmentStatus      ReEnrollmnentConfig `json:"ReenrollmentStatus,omitempty"`
	SetNewPasswordAllowed   bool                `json:"SetNewPasswordAllowed,omitempty"`
	Password                StorePasswordConfig `json:"Password,omitempty"`
}

// PropertyDefinition defines property filds associated with a certificate store type, and is returned by the
// GetCertStoreType method
type PropertyDefinition struct {
	StoreTypeID  int    `json:"StoreTypeID"`
	Name         string `json:"Name"`
	DisplayName  string `json:"DisplayName"`
	Type         string `json:"Type"`
	DependsOn    string `json:"DependsOn"`
	DefaultValue string `json:"DefaultValue"`
	Required     bool   `json:"Required"`
}

// CreateStoreResponse contains the response elements returned from the CreateStore method.
type CreateStoreResponse struct {
	Id                      string              `json:"Id"`
	ContainerId             int                 `json:"ContainerId"`
	ClientMachine           string              `json:"ClientMachine"`
	Storepath               string              `json:"Storepath"`
	CertStoreInventoryJobId string              `json:"CertStoreInventoryJobId"`
	CertStoreType           int                 `json:"cert_store_type"`
	Approved                bool                `json:"Approved"`
	CreateIfMissing         bool                `json:"CreateIfMissing"`
	PropertiesString        string              `json:"Properties"`
	Properties              map[string]string   `json:"-"`
	AgentId                 string              `json:"AgentId"`
	AgentAssigned           bool                `json:"AgentAssigned"`
	ContainerName           string              `json:"ContainerName"`
	InventorySchedule       InventorySchedule   `json:"InventorySchedule"`
	ReenrollmentStatus      ReEnrollmnentConfig `json:"ReenrollmentStatus"`
	SetNewPasswordAllowed   bool                `json:"SetNewPasswordAllowed"`
}

// UpdateStoreResponse contains the response elements returned from the UpdateStore method.
type UpdateStoreResponse struct{ CreateStoreResponse }

// AddCertificateToStore contains configuration content required to add a certificate to one or multiple certificate
// stores located inside Keyfactor Command.
type AddCertificateToStore struct {
	// An integer containing the Keyfactor Command reference ID of the certificate to be added to the certificate store(s).
	CertificateId int `json:"CertificateId"`

	// An array of certificate store GUIDs to identify the certificate stores to which the certificate should be added
	// and provide appropriate reference information for the certificate in the store.
	CertificateStores *[]CertificateStore `json:"CertificateStores,omitempty"`

	// The inventory schedule for the add job
	InventorySchedule *InventorySchedule `json:"Schedule,omitempty"`

	// An integer containing the Keyfactor Command reference ID of the certificate to be added to the certificate store(s).
	CollectionId int `json:"CollectionId,omitempty"`
}

// RemoveCertificateFromStore contains configuration data required to remove a certificate associated with a specific
// alias from one or more certificate stores.
type RemoveCertificateFromStore struct {
	// An array of certificate store GUIDs to identify the certificate stores to which the certificate should be added
	// and provide appropriate reference information for the certificate in the store.
	CertificateStores *[]CertificateStore `json:"CertificateStores"`

	// The inventory schedule for the add job
	InventorySchedule *InventorySchedule `json:"Schedule,omitempty"`

	// An integer containing the Keyfactor Command reference ID of the certificate to be added to the certificate store(s).
	CollectionId int `json:"CollectionId,omitempty"`
}

// CertificateStore contains configuration used by AddCertificateToStore and RemoveCertificateFromStore to configure
// the certificate stores that a certificate should be added to.
type CertificateStore struct {
	// A string containing the GUID for the certificate store to which the certificate should be added.
	CertificateStoreId string `json:"CertificateStoreId,omitempty"`

	// A string providing an alias to be used for the certificate upon entry into the certificate store. The function of the alias varies depending on the certificate store type.
	Alias string `json:"Alias,omitempty"`

	// A Boolean that sets whether a certificate in the store with the Alias provided should be overwritten with the certificate being added (true) or not (false). The default is false
	Overwrite bool `json:"Overwrite,omitempty"`

	// The password to set on the entry within the certificate store, if applicable. Only select certificate stores support entry passwords (e.g. Java keystores).
	EntryPassword *EntryPassword `json:"EntryPassword"`

	// Password used to secure certificate store, if it exists as a PKCS#12
	PfxPassword string `json:"PfxPassword,omitempty"`

	// A Boolean that sets whether to include the private key of the certificate in the certificate store if private keys are optional for the given certificate store (true) or not (false). The default is false.
	IncludePrivateKey bool `json:"IncludePrivateKey,omitempty"`
}

type EntryPassword struct {
	// A string containing the password. This value only needs to be supplied if you're storing your password in the Keyfactor Command database.
	SecretValue string `json:"SecretValue,omitempty"`

	// The parameters required by your PAM provider, containing the information that identifies the location of the password in the PAM solution.
	Parameters struct{} `json:"Parameters,omitempty"`

	// An integer that identifies the PAM provider used to store the password.
	Provider int `json:"Provider,omitempty"`
}
