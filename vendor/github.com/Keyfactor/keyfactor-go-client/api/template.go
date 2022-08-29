package api

import (
	"encoding/json"
	"errors"
	"fmt"
)

// GetTemplate takes arguments for a template ID used to facilitate the retrieval
// of certificate template context. The primary query required to get certificate context is the template ID. A pointer
//to a GetTemplateResponse structure is returned, containing the template context.
func (c *Client) GetTemplate(Id interface{}) (*GetTemplateResponse, error) {
	if Id == 0 {
		return nil, errors.New("template id required to get template")
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	endpoint := "Templates/" + fmt.Sprintf("%d", Id) // Append ID to complete endpoint

	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Query:    nil,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	jsonResp := &GetTemplateResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, err
}

// GetTemplates asks Keyfactor for a complete list of known certificate templates. A list of
// GetTemplateResponse structures is returned, containing the template context.
func (c *Client) GetTemplates() ([]GetTemplateResponse, error) {

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: "Templates/",
		Headers:  headers,
		Query:    nil,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	var jsonResp []GetTemplateResponse
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, err
}

// UpdateTemplate takes arguments for a UpdateTemplateArg structure used to facilitate the modification
// of a certificate template. Required parameters for this function are elements of UpdateTemplateArg that can't be set to nil. A pointer
// to a UpdateTemplateResponse structure is returned, containing the template context.
func (c *Client) UpdateTemplate(uta *UpdateTemplateArg) (*UpdateTemplateResponse, error) {

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "PUT",
		Endpoint: "Templates/",
		Headers:  headers,
		Query:    nil,
		Payload:  uta,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	jsonResp := &UpdateTemplateResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, err
}
