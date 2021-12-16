package keyfactor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

// CreateStoreFctArgs holds the function arguments used for calling the CreateStore method.
type CreateStoreFctArgs struct {
	ContainerId             *int                 `json:"ContainerId,omitempty"`
	ClientMachine           string               `json:"ClientMachine"`
	StorePath               string               `json:"StorePath"`
	CertStoreInventoryJobId *string              `json:"CertStoreInventoryJobId,omitempty"`
	CertStoreType           int                  `json:"CertStoreType"`
	Approved                *bool                `json:"Approved,omitempty"`
	CreateIfMissing         *bool                `json:"CreateIfMissing,omitempty"`
	PropertiesString        string               `json:"Properties,omitempty"` // This is sent to Keyfactor
	Properties              []StringTuple        `json:"-"`                    // Function args uses this
	AgentId                 string               `json:"AgentId"`
	AgentAssigned           *bool                `json:"AgentAssigned,omitempty"`
	ContainerName           *string              `json:"ContainerName,omitempty"`
	InventorySchedule       *InventorySchedule   `json:"InventorySchedule,omitempty"`
	ReEnrollmentStatus      *ReEnrollmnentConfig `json:"ReEnrollmentStatus,omitempty"`
	SetNewPasswordAllowed   *bool                `json:"SetNewPasswordAllowed,omitempty"`
	Password                *StorePasswordConfig `json:"Password,omitempty"`
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
	Data               bool          `json:"Data"`
	AgentId            string        `json:"AgentId"`
	Message            string        `json:"Message"`
	JobProperties      []interface{} `json:"JobProperties"`
	CustomAliasAllowed int           `json:"CustomAliasAllowed"`
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
	Properties              []StringTuple       `json:"-"` // Usable form for other processes
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
	Properties              []StringTuple       `json:"-"`
	AgentId                 string              `json:"AgentId"`
	AgentAssigned           bool                `json:"AgentAssigned"`
	ContainerName           string              `json:"ContainerName"`
	InventorySchedule       InventorySchedule   `json:"InventorySchedule"`
	ReenrollmentStatus      ReEnrollmnentConfig `json:"ReenrollmentStatus"`
	SetNewPasswordAllowed   bool                `json:"SetNewPasswordAllowed"`
}

// CreateStore takes arguments for CreateStoreFctArgs and APIClient to facilitate the creation
// of all store types supported by a customer Keyfactor Command instance. Note that various certificate
// store types require different property arguments, and careful attention should be taken to ensure that
// all required elements are included. Required arguments for this method are:
//  - ClientMachine : string
//  - StorePath     : string
//  - Properties    : []StringTuple *Note - Method converts this array of StringTuples to a JSON string if provided
//  - AgentId       : string
func CreateStore(ca *CreateStoreFctArgs, api *APIClient) (*CreateStoreResponse, error) {
	log.Println("[INFO] Creating new certificate store with Keyfactor")

	// Validate that the required fields are present
	err := validateCreateStoreArgs(ca)
	if err != nil {
		return nil, err
	}

	// API doesn't know what a StringTuple type is. Convert this type to an array of interfaces
	// that the JSON library can serialize. Then, serialize to JSON, and convert to string.
	if ca.PropertiesString == "" {
		propertiesInterface := buildPropertiesInterface(ca.Properties)
		propertiesJson, err := json.Marshal(propertiesInterface)
		if err != nil {
			return nil, err
		}
		ca.PropertiesString = string(propertiesJson)
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
		Endpoint: "/KeyfactorAPI/CertificateStores",
		Headers:  headers,
		Payload:  &ca,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &CreateStoreResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
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

func validateCreateStoreArgs(ca *CreateStoreFctArgs) error {
	if ca.ClientMachine == "" {
		return errors.New("client machine is required for creation of new certificate store")
	}
	if ca.StorePath == "" {
		return errors.New("store path is required for creation of new certificate store")
	}
	if ca.Properties == nil {
		return errors.New("properties attribute is required for creation of new certificate store")
	}
	if ca.AgentId == "" {
		return errors.New("orchestrator agent id is required for creation of new certificate store")
	}

	return nil
}

// buildPropertiesInterface takes argument for an array of StringTuple and returns an interface of the associated values
// in map[string]interface{} elements.
func buildPropertiesInterface(properties []StringTuple) interface{} {
	// Create temporary array of interfaces
	// When updating a property in Keyfactor, API expects {"key": {"value": "key-value"}} - Build this interface
	propertiesInterface := make(map[string]interface{})
	for _, property := range properties {
		inside := make(map[string]interface{})
		inside["value"] = property.Elem2             // Create {"value": "key-value"} interface
		propertiesInterface[property.Elem1] = inside // Create {"key": {"value": "key-value"}} interface
	}
	return propertiesInterface
}

// GetCertStoreType takes arguments for a certificate store type ID and APIClient to facilitate a call to Keyfactor
// that retrieves certificate store context assicated with a store type ID
func GetCertStoreType(id int, api *APIClient) (*CertStoreTypeResponse, error) {
	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	endpoint := fmt.Sprintf("/KeyfactorAPI/CertificateStoreTypes/%d", id)
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] GET succeeded with response code %d", resp.StatusCode)
		jsonResp := &CertStoreTypeResponse{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
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

// DeleteCertificateStore takes arguments for a certificate store ID and APIClient to facilitate a call to Keyfactor
// that deletes a certificate store. Only the store ID is required.
func DeleteCertificateStore(storeId string, api *APIClient) error {
	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	endpoint := "KeyfactorAPI/CertificateStores/" + fmt.Sprintf("%s", storeId) // Append GUID to complete endpoint
	keyfactorAPIStruct := &APIRequest{
		KFClient: api,
		Method:   "DELETE",
		Endpoint: endpoint,
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNoContent {
		log.Printf("[DEBUG] DELETE succeeded with response code %d", resp.StatusCode)
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

// GetCertificateStoreByID takes arguments for a certificate store ID and APIClient to facilitate a call to Keyfactor
// that retrieves a certificate store context. Only the store ID is required. A pointer to a GetStoreByIDResp struct
// is returned that contains information on the certificate store.
func GetCertificateStoreByID(storeId string, client *APIClient) (*GetStoreByIDResp, error) {
	// Set Keyfactor-specific headers
	log.Println("[TRACE] Setting request headers")
	headers := &APIHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	log.Println("[TRACE] Creating request struct for Keyfactor client")
	endpoint := "KeyfactorAPI/CertificateStores/" + fmt.Sprintf("%s", storeId) // Append GUID to complete endpoint
	keyfactorAPIStruct := &APIRequest{
		KFClient: client,
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := SendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] GET succeeded with response code %d", resp.StatusCode)
		jsonResp := &GetStoreByIDResp{}
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		if err != nil {
			return nil, err
		}
		jsonResp.Properties = unmarshalPropertiesString(jsonResp.PropertiesString)
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

// unmarshalPropertiesString unmarshalls a JSON string and serializes it into an array of StringTuple.
func unmarshalPropertiesString(properties string) []StringTuple {
	if properties != "" {
		// First, unmarshal JSON properties string to []interface{}
		var tempInterface interface{}
		if err := json.Unmarshal([]byte(properties), &tempInterface); err != nil {
			return make([]StringTuple, 0, 0)
		}
		// Then, iterate through each key:value pair and serialize into array of StringTuple
		var propertiesStringTuple []StringTuple
		for key, value := range tempInterface.(map[string]interface{}) {
			temp := StringTuple{
				Elem1: key,
				Elem2: value.(string),
			}
			propertiesStringTuple = append(propertiesStringTuple, temp)
		}
		return propertiesStringTuple
	}

	return make([]StringTuple, 0, 0)
}
