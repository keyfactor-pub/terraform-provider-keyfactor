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
		Endpoint: "Security/Identities",
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	var jsonResp []GetSecurityIdentityResponse
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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
		Endpoint: "Security/Identities",
		Headers:  headers,
		Payload:  csia,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	jsonResp := &CreateSecurityIdentityResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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

	endpoint := "Security/Identities/" + fmt.Sprintf("%d", id) // Append ID to complete endpoint
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

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("[ERROR] Something unexpected happened, %s call to %s returned status %d", keyfactorAPIStruct.Method, keyfactorAPIStruct.Endpoint, resp.StatusCode)
	}
	return nil
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

	endpoint := "Security/Roles/" + fmt.Sprintf("%d", id) // Append ID to complete endpoint
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

	jsonResp := &GetSecurityRolesResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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

	endpoint := "Security/Roles/" + fmt.Sprintf("%d", id) // Append ID to complete endpoint
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

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("[ERROR] Something unexpected happened, %s call to %s returned status %d", keyfactorAPIStruct.Method, keyfactorAPIStruct.Endpoint, resp.StatusCode)
	}
	return nil
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
		Endpoint: "Security/Roles",
		Headers:  headers,
		Payload:  input,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	jsonResp := &CreateSecurityRoleResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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
		Endpoint: "Security/Roles",
		Headers:  headers,
		Payload:  input,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	jsonResp := &UpdateSecurityRoleResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}
