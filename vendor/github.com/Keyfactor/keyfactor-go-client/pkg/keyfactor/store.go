package keyfactor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

// CreateStore takes arguments for CreateStoreFctArgs to facilitate the creation
// of all store types supported by a customer Keyfactor Command instance. Note that various certificate
// store types require different property arguments, and careful attention should be taken to ensure that
// all required elements are included. Required arguments for this method are:
//  - ClientMachine : string
//  - StorePath     : string
//  - Properties    : []StringTuple *Note - Method converts this array of StringTuples to a JSON string if provided
//  - AgentId       : string
func (c *Client) CreateStore(ca *CreateStoreFctArgs) (*CreateStoreResponse, error) {
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
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/CertificateStores",
		Headers:  headers,
		Payload:  &ca,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// UpdateStore takes arguments for UpdateStoreFctArgs to facilitate the adjustment of a certificate store
// associated with a Keyfactor Command instance. Note that various certificate
// store types require different property arguments, and careful attention should be taken to ensure that
// all required elements are included. Required arguments for this method are:
//  - ClientMachine : string
//  - StorePath     : string
//  - Properties    : []StringTuple *Note - Method converts this slice of StringTuples to a JSON string if provided
//  - AgentId       : string
func (c *Client) UpdateStore(ua *UpdateStoreFctArgs) (*UpdateStoreResponse, error) {
	log.Println("[INFO] Creating new certificate store with Keyfactor")

	// Validate that the required fields are present
	err := validateUpdateStoreArgs(ua)
	if err != nil {
		return nil, err
	}

	// API doesn't know what a StringTuple type is. Convert this type to an array of interfaces
	// that the JSON library can serialize. Then, serialize to JSON, and convert to string.
	if ua.PropertiesString == "" {
		propertiesInterface := buildPropertiesInterface(ua.Properties)
		propertiesJson, err := json.Marshal(propertiesInterface)
		if err != nil {
			return nil, err
		}
		ua.PropertiesString = string(propertiesJson)
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "Put",
		Endpoint: "/KeyfactorAPI/CertificateStores",
		Headers:  headers,
		Payload:  &ua,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &UpdateStoreResponse{}
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

// GetCertStoreType takes arguments for a certificate store type ID to facilitate a call to Keyfactor
// that retrieves certificate store context assicated with a store type ID
func (c *Client) GetCertStoreType(id int) (*CertStoreTypeResponse, error) {
	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := fmt.Sprintf("/KeyfactorAPI/CertificateStoreTypes/%d", id)
	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// DeleteCertificateStore takes arguments for a certificate store ID to facilitate a call to Keyfactor
// that deletes a certificate store. Only the store ID is required.
func (c *Client) DeleteCertificateStore(storeId string) error {
	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := "KeyfactorAPI/CertificateStores/" + fmt.Sprintf("%s", storeId) // Append GUID to complete endpoint
	keyfactorAPIStruct := &request{
		Method:   "DELETE",
		Endpoint: endpoint,
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// GetCertificateStoreByID takes arguments for a certificate store ID to facilitate a call to Keyfactor
// that retrieves a certificate store context. Only the store ID is required. A pointer to a GetStoreByIDResp struct
// is returned that contains information on the certificate store.
func (c *Client) GetCertificateStoreByID(storeId string) (*GetStoreByIDResp, error) {
	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := "KeyfactorAPI/CertificateStores/" + fmt.Sprintf("%s", storeId) // Append GUID to complete endpoint
	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

func validateCreateStoreArgs(ca *CreateStoreFctArgs) error {
	if ca.ClientMachine == "" {
		return errors.New("client machine is required for creation of new certificate store")
	}
	if ca.StorePath == "" {
		return errors.New("store path is required for creation of new certificate store")
	}
	if ca.AgentId == "" {
		return errors.New("orchestrator agent id is required for creation of new certificate store")
	}

	return nil
}

func validateUpdateStoreArgs(ca *UpdateStoreFctArgs) error {
	if ca.ClientMachine == "" {
		return errors.New("client machine is required for creation of new certificate store")
	}
	if ca.StorePath == "" {
		return errors.New("store path is required for creation of new certificate store")
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
