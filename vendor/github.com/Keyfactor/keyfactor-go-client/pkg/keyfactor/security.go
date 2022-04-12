package keyfactor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

// GetSecurityIdentities hits the /Security/Identities endpoint with a GET request and returns a list of
// GetSecurityIdentityResponse structs. The function takes no arguments.
func (c *Client) GetSecurityIdentities() ([]GetSecurityIdentityResponse, error) {
	log.Println("[INFO] Getting Keyfactor security identity list")

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: "/KeyfactorAPI/Security/Identities",
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] GET succeeded with response code %d", resp.StatusCode)
		var jsonResp []GetSecurityIdentityResponse
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

// CreateSecurityIdentity hits the /Security/Identities endpoint with a POST request to create a new Keyfactor security
// and returns a CreateSecurityIdentityResponse struct. The function takes argument for a CreateSecurityIdentityArg struct
func (c *Client) CreateSecurityIdentity(csia *CreateSecurityIdentityArg) (*CreateSecurityIdentityResponse, error) {
	log.Println("[INFO] Creating new Keyfactor security identity")

	// Verify argument
	if csia == nil || csia.AccountName == "" {
		return nil, errors.New("invalid input received for security identity creation")
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
		Endpoint: "/KeyfactorAPI/Security/Identities",
		Headers:  headers,
		Payload:  csia,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] POST succeeded with response code %d", resp.StatusCode)
		jsonResp := &CreateSecurityIdentityResponse{}
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

// DeleteSecurityIdentity takes arguments for a security identity ID, and makes an associated call to Keyfactor to
// delete the identity.
func (c *Client) DeleteSecurityIdentity(id int) error {
	log.Printf("[INFO] Deleting Keyfactor security identity with ID %d", id)

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := "KeyfactorAPI/Security/Identities/" + fmt.Sprintf("%d", id) // Append ID to complete endpoint
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

func (c *Client) GetSecurityRole(id int) (*GetSecurityRolesResponse, error) {
	log.Printf("[INFO] Getting Keyfactor security role with ID %d", id)

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := "KeyfactorAPI/Security/Roles/" + fmt.Sprintf("%d", id) // Append ID to complete endpoint
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
		log.Printf("[DEBUG] %s succeeded with response code %d", keyfactorAPIStruct.Method, resp.StatusCode)
		jsonResp := &GetSecurityRolesResponse{}
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

// DeleteSecurityRole takes arguments for a security role ID, and makes an associated call to Keyfactor to
// delete the role.
func (c *Client) DeleteSecurityRole(id int) error {
	log.Printf("[INFO] Deleting Keyfactor security role with ID %d", id)

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := "KeyfactorAPI/Security/Roles/" + fmt.Sprintf("%d", id) // Append ID to complete endpoint
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
		log.Printf("[DEBUG] %s succeeded with response code %d", keyfactorAPIStruct.Method, resp.StatusCode)
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

// CreateSecurityRole creates a new Keyfacor security role. This function takes argument for a CreateSecurityRoleArg
// struct and returns a CreateSecurityRoleResponse struct.
func (c *Client) CreateSecurityRole(input *CreateSecurityRoleArg) (*CreateSecurityRoleResponse, error) {
	log.Println("[INFO] Creating new Keyfactor security role")

	// Verify argument
	if input == nil || input.Name == "" || input.Description == "" {
		return nil, errors.New("invalid input received for security role creation")
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
		Endpoint: "/KeyfactorAPI/Security/Roles",
		Headers:  headers,
		Payload:  input,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] %s succeeded with response code %d", keyfactorAPIStruct.Method, resp.StatusCode)
		jsonResp := &CreateSecurityRoleResponse{}
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

// UpdateSecurityRole updates the Keyfacor security role. This function takes argument for a CreateSecurityRoleArg
// struct and returns a CreateSecurityRoleResponse struct.
func (c *Client) UpdateSecurityRole(input *UpdatteSecurityRoleArg) (*UpdateSecurityRoleResponse, error) {
	log.Printf("[INFO] Updating Keyfactor security role with ID %d", input.Id)

	// Verify argument
	if input == nil {
		return nil, errors.New("update security role - argument struct is nil")
	}
	if input.Name == "" {
		return nil, errors.New("update security role - role name is blank")
	}
	if input.Description == "" {
		return nil, errors.New("update security role - role description is blank")
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "PUT",
		Endpoint: "/KeyfactorAPI/Security/Roles",
		Headers:  headers,
		Payload:  input,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DEBUG] %s succeeded with response code %d", keyfactorAPIStruct.Method, resp.StatusCode)
		jsonResp := &UpdateSecurityRoleResponse{}
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
