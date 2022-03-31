package keyfactor

// SANs holds arrays of strings associated with IPv4 (IP4), IPv6 (IP6), DNS, and URI SANs.
type SANs struct {
	IP4 []string `json:"ip4,omitempty"`
	IP6 []string `json:"ip6,omitempty"`
	DNS []string `json:"dns,omitempty"`
	URI []string `json:"uri,omitempty"`
}

// EnrollPFXFctArgs holds the function arguments used for calling the EnrollPFX method.
type EnrollPFXFctArgs struct {
	CustomFriendlyName          string
	KeyPassword                 string
	PopulateMissingValuesFromAD bool
	CertificateAuthority        string
	Template                    string
	IncludeChain                bool
	RenewalCertificateId        int
	CertFormat                  string
	CertificateSubject          CertificateSubject
	CertificateMetadata         []StringTuple
	CertificateSANs             *SANs
}

// EnrollCSRFctArgs holds the function arguments used for calling the EnrollCSR method.
type EnrollCSRFctArgs struct {
	CSR                  string
	CertificateAuthority string
	Template             string
	IncludeChain         bool
	CertFormat           string
	CertificateMetadata  []StringTuple
	CertificateSANs      *SANs
}

// RevokeCertArgs holds the function arguments used for calling the RevokeCert method.
type RevokeCertArgs struct {
	CertificateIds []int  `json:"CertificateIds"`
	Reason         int    `json:"Reason"`
	Comment        string `json:"Comment"`
	EffectiveDate  string `json:"EffectiveDate"`
	CollectionId   int    `json:"CollectionId,omitempty"`
}

// DownloadCertArgs holds the function arguments used for calling the DownloadCertificate method.
type DownloadCertArgs struct {
	CertID       int
	SerialNumber string
	IssuerDN     string
	Thumbprint   string
	IncludeChain bool
	CollectionId int
	CertFormat   string
}

// UpdateMetadataArgs holds the function arguments used for calling the UpdateMetadata method.
type UpdateMetadataArgs struct {
	CertID              int                    `json:"Id"`
	CertificateMetadata []StringTuple          `json:"-"`
	Metadata            map[string]interface{} `json:"Metadata"`
	CollectionId        int                    `json:"CollectionId"`
}

// GetCertificateContextArgs holds the function arguments used for calling the GetCertificateContext method.
type GetCertificateContextArgs struct {
	IncludeMetadata  *bool // Query
	IncludeLocations *bool // Query
	CollectionId     *int  // Query
	Id               int   // Query
}

// DeployPFXArgs holds the function arguments used for calling the DeployPFXCertificate method.
type DeployPFXArgs struct {
	StoreIds      []string     `json:"StoreIds"`
	Password      string       `json:"Password"`
	StoreTypes    []StoreTypes `json:"StoreTypes"`
	CertificateId int          `json:"CertificateId"`
	RequestId     int          `json:"RequestId"`
	JobTime       *string      `json:"JobTime,omitempty"`
}

// RecoverCertArgs holds the function arguments used for calling the RevokeCert method.
type RecoverCertArgs struct {
	CertId       int    `json:"CertId,omitempty"`
	CertFormat   string `json:"-"` // Header
	Password     string `json:"Password,omitempty"`
	SerialNumber string `json:"SerialNumber,omitempty"`
	IssuerDN     string `json:"IssuerDN,omitempty"`
	Thumbprint   string `json:"Thumbprint,omitempty"`
	IncludeChain bool   `json:"IncludeChain,omitempty"`
}

// StoreTypes holds necessary store type metadata for creating and deploying certificates.
type StoreTypes struct {
	StoreTypeId int       `json:"StoreTypeId"`
	Alias       *string   `json:"Alias,omitempty"`
	Overwrite   *bool     `json:"Overwrite,omitempty"`
	Properties  *[]string `json:"Properties,omitempty"`
}

// DeployPFXResp holds response data from the DeployPFXCertificate method.
type DeployPFXResp struct {
	SuccessfulStores []string `json:"SuccessfulStores"`
	FailedStores     []string `json:"FailedStores"`
}

// CertificateSubject contains string elements for X.509V3 certificate distinguished name (subject)
type CertificateSubject struct {
	SubjectCommonName         string
	SubjectLocality           string
	SubjectOrganization       string
	SubjectCountry            string
	SubjectOrganizationalUnit string
	SubjectState              string
}

// enrollPFXBody is the API POST request body for PFX enrollment (EnrollPFX).
type enrollPFXBody struct {
	CustomFriendlyName          string                 `json:"CustomFriendlyName,omitempty"`
	Password                    string                 `json:"Password"`
	PopulateMissingValuesFromAD bool                   `json:"PopulateMissingValuesFromAD"`
	Subject                     string                 `json:"Subject"`
	IncludeChain                bool                   `json:"IncludeChain"`
	RenewalCertificateId        int                    `json:"RenewalCertificateId,omitempty"`
	CertificateAuthority        string                 `json:"CertificateAuthority"`
	Timestamp                   string                 `json:"Timestamp"`
	Template                    string                 `json:"Template"`
	SANs                        *SANs                  `json:"SANs,omitempty"`
	Metadata                    map[string]interface{} `json:"Metadata,omitempty"`
}

// enrollCSRBody is the API POST request body for PFX enrollment (EnrollCSR).
type enrollCSRBody struct {
	CSR                  string
	Timestamp            string                 `json:"Timestamp"`
	Template             string                 `json:"Template"`
	CertificateAuthority string                 `json:"CertificateAuthority"`
	IncludeChain         bool                   `json:"IncludeChain"`
	SANs                 *SANs                  `json:"SANs"`
	Metadata             map[string]interface{} `json:"Metadata"`
}

// downloadCertificateBody is the API POST request body for PFX enrollment (DownloadCertificate).
type downloadCertificateBody struct {
	CertID       int
	SerialNumber string
	IssuerDN     string
	Thumbprint   string
	IncludeChain bool
}

// EnrollResponse is the outer certificate enrollment response. When Enroll functions are called, the certificates are
// placed inside the Certificates element, and certificate information is placed inside CertificateInformation
type EnrollResponse struct {
	Certificates           []string
	CertificateInformation CertificateInformation `json:"CertificateInformation"`
}

// CertificateInformation contains response data from the Enroll methods.
type CertificateInformation struct {
	SerialNumber       string      `json:"SerialNumber"`
	IssuerDN           string      `json:"IssuerDN"`
	Thumbprint         string      `json:"Thumbprint"`
	KeyfactorID        int         `json:"KeyfactorID"`
	KeyfactorRequestID int         `json:"KeyfactorRequestId"`
	PKCS12Blob         string      `json:"PKCS12Blob"`
	Certificates       []string    `json:"Certificates"`
	RequestDisposition string      `json:"RequestDisposition"`
	DispositionMessage string      `json:"DispositionMessage"`
	EnrollmentContext  interface{} `json:"EnrollmentContext"`
}

// GetCertificateResponse contains the response elements returned from the GetCertificateContext method.
type GetCertificateResponse struct {
	Id                       int    `json:"Id"`
	Thumbprint               string `json:"Thumbprint"`
	SerialNumber             string `json:"SerialNumber"`
	IssuedDN                 string `json:"IssuedDN"`
	IssuedCN                 string `json:"IssuedCN"`
	ImportDate               string `json:"ImportDate"`
	NotBefore                string `json:"NotBefore"`
	NotAfter                 string `json:"NotAfter"`
	IssuerDN                 string `json:"IssuerDN"`
	PrincipalId              string `json:"PrincipalId"`
	TemplateId               int    `json:"TemplateId"`
	CertState                int    `json:"CertState"`
	KeySizeInBits            int    `json:"KeySizeInBits"`
	KeyType                  int    `json:"KeyType"`
	RequesterId              int    `json:"RequesterId"`
	IssuedOU                 string `json:"IssuedOU"`
	KeyUsage                 int    `json:"KeyUsage"`
	SigningAlgorithm         string `json:"SigningAlgorithm"`
	CertStateString          string `json:"CertStateString"`
	KeyTypeString            string `json:"KeyTypeString"`
	RevocationEffDate        string `json:"RevocationEffDate"`
	RevocationReason         int    `json:"RevocationReason"`
	RevocationComment        string `json:"RevocationComment"`
	CertificateAuthorityId   int    `json:"CertificateAuthorityId"`
	CertificateAuthorityName string `json:"CertificateAuthorityName"`
	TemplateName             string `json:"TemplateName"`
	ArchivedKey              bool   `json:"ArchivedKey"`
	HasPrivateKey            bool   `json:"HasPrivateKey"`
	PrincipalName            string `json:"PrincipalName"`
	CertRequestId            int    `json:"CertRequestId"`
	RequesterName            string `json:"RequesterName"`
	ContentBytes             string `json:"ContentBytes"`
	ExtendedKeyUsages        []interface{}
	SubjectAltNameElements   []SubjectAltNameElements `json:"SubjectAltNameElements"`
	CRLDistributionPoints    []CRLDistributionPoints  `json:"CRLDistributionPoints"`
	LocationsCount           []LocationsCount         `json:"LocationsCount"`
	SSLLocations             []SSLLocations           `json:"SSLLocations"`
	Locations                []CertificateLocations   `json:"Locations"`
	Metadata                 interface{}              `json:"Metadata"`
	CertificateKeyId         int                      `json:"CertificateKeyId"`
	CARowIndex               int                      `json:"CARowIndex"`
	DetailedKeyUsage         []DetailedKeyUsage       `json:"detailed_key_usage"`
	KeyRecoverable           bool                     `json:"KeyRecoverable"`
}

// RecoverCertResponse contains the response elements returned from the RecoverCertificate method.
type RecoverCertResponse struct {
	PFX      string `json:"PFX"`
	FileName string `json:"FileName"`
}

// DetailedKeyUsage contains key useage data returned by the GetCertificateContext method.
type DetailedKeyUsage struct {
	CrlSign          bool   `json:"CrlSign,omitempty"`
	DataEncipherment bool   `json:"DataEncipherment,omitempty"`
	DecipherOnly     bool   `json:"DecipherOnly,omitempty"`
	DigitalSignature bool   `json:"DigitalSignature,omitempty"`
	EncipherOnly     bool   `json:"EncipherOnly,omitempty"`
	KeyAgreement     bool   `json:"KeyAgreement,omitempty"`
	KeyCertSign      bool   `json:"KeyCertSign,omitempty"`
	KeyEncipherment  bool   `json:"KeyEncipherment,omitempty"`
	NonRepudiation   bool   `json:"NonRepudiation,omitempty"`
	HexCode          string `json:"HexCode,omitempty"`
}

// CertificateLocations contains response and request data for the GetCertificateContext and DeployPFXCertificate
// methods
type CertificateLocations struct {
	StoreMachine string `json:"StoreMachine,omitempty"`
	StorePath    string `json:"StorePath,omitempty"`
	StoreType    int    `json:"StoreType,omitempty"`
	Alias        string `json:"Alias,omitempty"`
	ChainLevel   int    `json:"ChainLevel,omitempty"`
	CertStoreId  string `json:"CertStoreId,omitempty"`
}

// SSLLocations contains detailed information on the locations that the certificate was found in a scan.
type SSLLocations struct {
	StorePath   string `json:"StorePath,omitempty"`
	AgentPool   string `json:"AgentPool,omitempty"`
	IPAddress   string `json:"IPAddress,omitempty"`
	Port        int    `json:"Port,omitempty"`
	NetworkName string `json:"NetworkName,omitempty"`
}

// LocationsCount contains details on what kind of and how many stores the certificate is deployed inside.
type LocationsCount struct {
	Type  string `json:"Type,omitempty"`
	Count int    `json:"Count,omitempty"`
}

// CRLDistributionPoints contains details on the CRL distribution and is returned inside GetCertificateResponse with
// the GetCertificateContext method.
type CRLDistributionPoints struct {
	Id      int    `json:"Id"`
	URL     string `json:"URL"`
	URLHash string `json:"URLHash"`
}

// SubjectAltNameElements contains detailed information on the SANs attached to a certificate, and is returned inside
// the GetCertificateContext method
type SubjectAltNameElements struct {
	Id        int    `json:"Id"`
	Value     string `json:"Value"`
	Type      int    `json:"Type"`
	ValueHash string `json:"ValueHash"`
}

// DownloadCertificateResponse holds a raw string containing a Base64 encoded certificate.
type DownloadCertificateResponse struct {
	Content string `json:"Content"`
}
