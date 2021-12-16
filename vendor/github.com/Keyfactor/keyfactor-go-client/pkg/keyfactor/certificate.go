package keyfactor

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

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

// revokeCertBody is the API POST request body for PFX enrollment (RevokeCert).
type revokeCertBody struct {
	CertificateIds []int  `json:"CertificateIds"`
	Reason         int    `json:"Reason"`
	Comment        string `json:"Comment"`
	EffectiveDate  string `json:"EffectiveDate"`
	CollectionId   int    `json:"CollectionId,omitempty"`
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

// GetTemplateResponse contains the response elements returned from the GetTemplate method.
type GetTemplateResponse struct {
	Id               int    `json:"Id,omitempty"`
	CommonName       string `json:"CommonName,omitempty"`
	TemplateName     string `json:"TemplateName,omitempty"`
	Oid              string `json:"Oid,omitempty"`
	KeySize          string `json:"KeySize,omitempty"`
	KeyType          string `json:"KeyType,omitempty"`
	ForestRoot       string `json:"ForestRoot,omitempty"`
	FriendlyName     string `json:"FriendlyName,omitempty"`
	KeyRetention     string `json:"KeyRetention,omitempty"`
	KeyRetentionDays int    `json:"KeyRetentionDays,omitempty"`
	KeyArchival      bool   `json:"KeyArchival,omitempty"`
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

// EnrollPFX takes arguments for EnrollPFXFctArgs and APIClient to facilitate a call to Keyfactor
// that enrolls a PFX certificate with the supplied arguments.
func EnrollPFX(ea *EnrollPFXFctArgs, api *APIClient) (*EnrollResponse, error) {
	log.Println("[INFO] Enrolling PFX certificate with Keyfactor")

	/* Ensure required inputs exist */
	if (ea.Template == "") || (ea.KeyPassword == "") || (ea.CertificateAuthority == "") || (ea.CertFormat == "") {
		return nil, errors.New("invalid or nonexistent values required for pfx enrollment")
	}

	/* Build subject */
	subject, err := createSubject(ea.CertificateSubject)
	if err != nil {
		return nil, err
	}

	// Once required fields are found, create request body
	log.Println("[TRACE] Creating request body")
	payload := &enrollPFXBody{
		CustomFriendlyName:          ea.CustomFriendlyName,
		Password:                    ea.KeyPassword,
		PopulateMissingValuesFromAD: ea.PopulateMissingValuesFromAD, // this field has default value
		Subject:                     subject,
		IncludeChain:                ea.IncludeChain, // IncludeChain has default value
		CertificateAuthority:        ea.CertificateAuthority,
		Timestamp:                   getTimestamp(),
		Template:                    ea.Template,
		SANs:                        ea.CertificateSANs,
		Metadata:                    mapTupleArrayToInterface(ea.CertificateMetadata),
	}

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", ea.CertFormat},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Enrollment/PFX",
		Headers:  headers,
		Payload:  &payload,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &EnrollResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		err = decodePKCS12Blob(jsonResp)
		if err != nil {
			return nil, err
		}
		return jsonResp, nil
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)
	return nil, errors.New(stringMessage)
}

// DownloadCertificate takes arguments for DownloadCertArgs and APIClient to facilitate a call to Keyfactor
// that downloads a certificate in the specified format.
// The download certificate endpoint requires one of the following to retrieve a cert:
//  - CertID
//  - Thumbprint
//  - SerialNumber AND IssuerDN
func DownloadCertificate(da *DownloadCertArgs, api *APIClient) (*DownloadCertificateResponse, error) {
	log.Println("[INFO] Downloading certificate")

	/* The download certificate endpoint requires one of the following to retrieve a cert:
		- CertID
		- Thumbprint
		- SerialNumber AND IssuerDN

	Check for this input
	*/
	var validInput = false
	if da.CertID != 0 {
		validInput = true
	} else if da.Thumbprint != "" {
		validInput = true
	} else if (da.SerialNumber != "") && (da.IssuerDN != "") {
		validInput = true
	}
	if validInput != true {
		return nil, errors.New("invalid input received for cert download request")
	}

	log.Println("[TRACE] Creating request body")

	payload := &downloadCertificateBody{
		CertID:       da.CertID,
		SerialNumber: da.SerialNumber,
		IssuerDN:     da.IssuerDN,
		Thumbprint:   da.Thumbprint,
		IncludeChain: da.IncludeChain,
	}

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", da.CertFormat},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Certificates/Download",
		Headers:  headers,
		Payload:  &payload,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &DownloadCertificateResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		content, err := base64.StdEncoding.DecodeString(jsonResp.Content)
		if err != nil {
			return nil, err
		}
		jsonResp.Content = string(content)

		return jsonResp, nil
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)

	return nil, errors.New(stringMessage)
}

// EnrollCSR takes arguments for EnrollCSRFctArgs and APIClient to enroll a passed Certificate Signing
// Request with Keyfactor. An EnrollResponse containing a signed certificate is returned upon successful
// enrollment. Required fields to complete a CSR enrollment are:
//  - CSR                  : string
//  - Template             : string
//  - CertificateAuthority : string
func EnrollCSR(ea *EnrollCSRFctArgs, api *APIClient) (*EnrollResponse, error) {
	log.Println("[INFO] Signing CSR with Keyfactor")

	/* Ensure required inputs exist */
	if (ea.Template == "") || (ea.CertificateAuthority == "") {
		return nil, errors.New("invalid or nonexistent values required for csr enrollment")
	}

	log.Println("[TRACE] Creating request body")
	payload := &enrollCSRBody{
		CSR:                  ea.CSR,
		Timestamp:            getTimestamp(),
		Template:             ea.Template,
		CertificateAuthority: ea.CertificateAuthority,
		IncludeChain:         ea.IncludeChain,
		SANs:                 ea.CertificateSANs,
		Metadata:             mapTupleArrayToInterface(ea.CertificateMetadata),
	}

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", ea.CertFormat},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Enrollment/CSR",
		Headers:  headers,
		Payload:  &payload,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &EnrollResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		jsonResp.Certificates = jsonResp.CertificateInformation.Certificates
		return jsonResp, nil
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)

	return nil, errors.New(stringMessage)
}

// UpdateMetadata takes arguments for UpdateMetadataArgs and APIClient to facilitate the
// updating of metadata fields in Keyfactor. It returns nil upon successful revocation,
// and an error if not. Required fields to update certificate metadata are:
//  - CertID              : int
//  - CertificateMetadata : []CertificateMetadata
func UpdateMetadata(um *UpdateMetadataArgs, api *APIClient) error {
	// Metadata in Keyfactor varies between deployments
	// Instead of hard coding possibilities, take array of string tuple types and create
	// string-indexed array of interfaces for JSON compilation
	um.Metadata = mapTupleArrayToInterface(um.CertificateMetadata)

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "PUT",
		Endpoint: "/KeyfactorAPI/Certificates/Metadata",
		Headers:  headers,
		Payload:  um,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNoContent {
		log.Printf("[DEBUG] PUT succeeded with response code %d", resp.StatusCode)
		return nil
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)
	return errors.New(stringMessage)
}

// mapTupleArrayToInterface takes an array of StringTuple structs and maps each element to
// a map[string]interface{}
func mapTupleArrayToInterface(i []StringTuple) map[string]interface{} {
	temp := make(map[string]interface{}, len(i)) // Create string-index-able interface array from tuple struct
	for _, field := range i {
		temp[field.Elem1] = field.Elem2
	}
	return temp
}

// RevokeCert takes arguments for RevokeCertArgs and APIClient to facilitate the revocation of
// all specified certificate IDs. It returns nil upon successful revocation, and an error if not.
// Required fields to revoke a list of certificates in Keyfactor are:
//  - CertificateIds : []int
//  - Comment        : string
func RevokeCert(ra *RevokeCertArgs, api *APIClient) error {
	log.Println("[INFO] Revoking certificates")
	for _, certs := range ra.CertificateIds {
		log.Printf("[TRACE] Revoking ID %d", certs)
	}

	// Fields required by revoke cert API request are cert ID & comment
	// Go initializes integers to 0, check for zero input
	if (ra.CertificateIds[0] == 0) && (ra.Comment == "") {
		return errors.New("invalid or nonexistent values required for certificate revocation")
	}

	if ra.EffectiveDate != "" {
		ra.EffectiveDate = getTimestamp()
	}

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Certificates/Revoke",
		Headers:  headers,
		Payload:  &ra,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNoContent {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		return nil
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)
	return errors.New(stringMessage)
}

// DeployPFXCertificate takes pointers to DeployPFXArgs and APIClient structs holding
// configuration data required for the deployment of a newly enrolled PFX certificate.
// It returns a pointer to a DeployPFXResp struct if successful, and an error message
// if not. Required fields to deploy a certificate to a store maintained by Keyfactor are:
//  - StoreIds      : []string
//  - Password      : string
//  - CertificateId : int
//  - RequestId     : int
func DeployPFXCertificate(args *DeployPFXArgs, api *APIClient) (*DeployPFXResp, error) {
	err := validateDeployPFXArgs(args)
	if err != nil {
		return nil, err
	}

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Enrollment/PFX/Deploy",
		Headers:  headers,
		Payload:  &args,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &DeployPFXResp{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		return jsonResp, err
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)

	return nil, errors.New(stringMessage)
}

// GetCertificateContext takes arguments for GetCertificateContextArgs and APIClient used to facilitate the retrieval
// of certificate context. The primary query required to get certificate context is the certificate ID. Include metadata
// and include locations add additional data, but can be set to false if they are unneeded. A pointer to a
// GetCertificateResponse structure is returned, containing the certificate context.
func GetCertificateContext(gca *GetCertificateContextArgs, api *APIClient) (*GetCertificateResponse, error) {
	if gca.Id == 0 {
		return nil, errors.New("keyfactor certificate id required to get certificate")
	}

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	// Construct URL query for /Certificates/{ID} requests
	var query *APIQuery
	if gca.IncludeLocations != nil || gca.CollectionId != nil || gca.IncludeMetadata != nil {
		query = &APIQuery{
			Query: []StringTuple{},
		}
		if gca.IncludeLocations != nil {
			query.Query = append(query.Query, StringTuple{
				"includeLocations", strconv.FormatBool(*gca.IncludeLocations),
			})
		}
		if gca.IncludeMetadata != nil {
			query.Query = append(query.Query, StringTuple{
				"includeMetadata", strconv.FormatBool(*gca.IncludeMetadata),
			})
		}
		if gca.CollectionId != nil {
			query.Query = append(query.Query, StringTuple{
				"collectionId", fmt.Sprintf("%d", gca.CollectionId),
			})
		}
	}

	endpoint := "/KeyfactorAPI/Certificates/" + fmt.Sprintf("%d", gca.Id) // Append ID to complete endpoint

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Query:    query,
		Payload:  nil,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] GET succeeded with response code %d", resp.StatusCode)

		jsonResp := &GetCertificateResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		return jsonResp, err
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)

	return nil, errors.New(stringMessage)
}

// GetTemplate takes arguments for a template ID and APIClient used to facilitate the retrieval
// of certificate template context. The primary query required to get certificate context is the template ID. A pointer
//to a GetTemplateResponse structure is returned, containing the template context.
func GetTemplate(Id int, api *APIClient) (*GetTemplateResponse, error) {
	if Id == 0 {
		return nil, errors.New("template id required to get template")
	}

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := "KeyfactorAPI/Templates/" + fmt.Sprintf("%d", Id) // Append ID to complete endpoint

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Query:    nil,
		Payload:  nil,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] GET succeeded with response code %d", resp.StatusCode)

		jsonResp := &GetTemplateResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		return jsonResp, err
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)

	return nil, errors.New(stringMessage)
}

// RecoverCertificate takes arguments for RecoverCertArgs and APIClient to facilitate a call to Keyfactor
// that recovers a certificate and associated private key (if retained) in the specified format.
// The download certificate endpoint requires one of the following to retrieve a cert:
//  - CertID
//  - Thumbprint
//  - SerialNumber AND IssuerDN
// Additionally, the certificate Password is required.
func RecoverCertificate(rca *RecoverCertArgs, api *APIClient) (*RecoverCertResponse, error) {
	log.Println("[INFO] Recovering certificate")
	/* The download certificate endpoint requires one of the following to retrieve a cert:
		- CertID
		- Thumbprint
		- SerialNumber AND IssuerDN

	Check for this input
	*/
	var validInput = false
	if rca.Password != "" {
		validInput = true
	}
	if rca.CertId != 0 {
		validInput = true
	} else if rca.Thumbprint != "" {
		validInput = true
	} else if (rca.SerialNumber != "") && (rca.IssuerDN != "") {
		validInput = true
	}
	if validInput != true {
		return nil, errors.New("invalid input received for cert download request")
	}

	log.Println("[TRACE] Creating request body")

	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", rca.CertFormat},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Certificates/Recover",
		Headers:  headers,
		Payload:  &rca,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &RecoverCertResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		content, err := base64.StdEncoding.DecodeString(jsonResp.PFX)
		if err != nil {
			return nil, err
		}
		jsonResp.PFX = string(content)

		return jsonResp, nil
	}

	var errorMessage interface{} // Decode JSON body to handle issue
	err = json.NewDecoder(resp.Body).Decode(&errorMessage)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
	stringMessage := fmt.Sprintf("%v", errorMessage)

	return nil, errors.New(stringMessage)
}

// createSubject builds the certificate subject string from a passed CertificateSubject argument.
func createSubject(cs CertificateSubject) (string, error) {
	var subject string

	if cs.SubjectCommonName != "" {
		subject = "CN=" + cs.SubjectCommonName + ","
	} else {
		return "", errors.New("build subject: common name required") // Common name is required!
	}
	if cs.SubjectOrganizationalUnit != "" {
		subject += "OU=" + cs.SubjectOrganizationalUnit + ","
	}
	if cs.SubjectOrganization != "" {
		subject += "O=" + cs.SubjectOrganization + ","
	}
	if cs.SubjectLocality != "" {
		subject += "L=" + cs.SubjectLocality + ","
	}
	if cs.SubjectState != "" {
		subject += "ST=" + cs.SubjectState + ","
	}
	if cs.SubjectCountry != "" {
		subject += "C=" + cs.SubjectCountry + ","
	}
	subject = strings.TrimRight(subject, ",") // remove trailing comma
	log.Printf("[DEBUG] createSubject(): Certificate subject created: %s\n", subject)
	return subject, nil
}

// validateDeployPFXArgs validates the arguments required to deploy a PFX certificate.
func validateDeployPFXArgs(dpfxa *DeployPFXArgs) error {
	if dpfxa.StoreIds == nil {
		return errors.New("store id required for deployment of pfx certificate")
	}
	if dpfxa.Password == "" {
		return errors.New("password required for deployment of pfx certificate")
	}
	if dpfxa.StoreTypes == nil {
		return errors.New("store type required for deployment of pfx certificate")
	}
	if dpfxa.CertificateId == 0 {
		return errors.New("certificate id required for deployment of pfx certificate")
	}
	if dpfxa.RequestId == 0 {
		return errors.New("request id required for deployment of pfx certificate")
	}
	return nil
}

// decodePKCS12Blob decodes a PKCS12 blob.
func decodePKCS12Blob(resp *EnrollResponse) error {
	log.Println("[TRACE] Decoding certificate")
	// Keyfactor returns base-64 PFX (PKCS#12) or zipped certificate. Decode here.
	if resp.CertificateInformation.PKCS12Blob != "" {
		cert, err := base64.StdEncoding.DecodeString(resp.CertificateInformation.PKCS12Blob)
		if err != nil {
			return err
		}
		temp := make([]string, 1) // Create temp 1 wide string array to hold certificate
		temp = append(temp, string(cert))
		resp.Certificates = temp
		return nil
	} else {
		resp.Certificates = nil
	}
	return nil
}
