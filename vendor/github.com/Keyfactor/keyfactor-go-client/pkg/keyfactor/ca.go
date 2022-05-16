package keyfactor

import (
	"encoding/json"
	"log"
)

// GetCAList returns a list of certificate authorities supported by the Keyfactor instance
func (c *Client) GetCAList() ([]CA, error) {
	log.Println("[INFO] Getting a list of CAs from Keyfactor instance")

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: "CertificateAuthority",
		Headers:  headers,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	var jsonResp []CA
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
}
