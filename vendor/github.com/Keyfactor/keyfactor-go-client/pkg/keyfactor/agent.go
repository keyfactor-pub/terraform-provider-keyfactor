package keyfactor

import (
	"encoding/json"
	"log"
)

// GetAgentList returns a list of orchestrators registered in the Keyfactor instance
func (c *Client) GetAgentList() ([]Agent, error) {
	log.Println("[INFO] Getting a list of agents registered in Keyfactor")

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: "Agents",
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	var jsonResp []Agent
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}
