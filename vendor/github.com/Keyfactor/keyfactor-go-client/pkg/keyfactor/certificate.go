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

// EnrollPFX takes arguments for EnrollPFXFctArgs to facilitate a call to Keyfactor
// that enrolls a PFX certificate with the supplied arguments.
func (c *Client) EnrollPFX(ea *EnrollPFXFctArgs) (*EnrollResponse, error) {
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
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", ea.CertFormat},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Enrollment/PFX",
		Headers:  headers,
		Payload:  &payload,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// DownloadCertificate takes arguments for DownloadCertArgs to facilitate a call to Keyfactor
// that downloads a certificate in the specified format.
// The download certificate endpoint requires one of the following to retrieve a cert:
//  - CertID
//  - Thumbprint
//  - SerialNumber AND IssuerDN
func (c *Client) DownloadCertificate(da *DownloadCertArgs) (*DownloadCertificateResponse, error) {
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

	payload := &downloadCertificateBody{
		CertID:       da.CertID,
		SerialNumber: da.SerialNumber,
		IssuerDN:     da.IssuerDN,
		Thumbprint:   da.Thumbprint,
		IncludeChain: da.IncludeChain,
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", da.CertFormat},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Certificates/Download",
		Headers:  headers,
		Payload:  &payload,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// EnrollCSR takes arguments for EnrollCSRFctArgs to enroll a passed Certificate Signing
// Request with Keyfactor. An EnrollResponse containing a signed certificate is returned upon successful
// enrollment. Required fields to complete a CSR enrollment are:
//  - CSR                  : string
//  - Template             : string
//  - CertificateAuthority : string
func (c *Client) EnrollCSR(ea *EnrollCSRFctArgs) (*EnrollResponse, error) {
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
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", ea.CertFormat},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Enrollment/CSR",
		Headers:  headers,
		Payload:  &payload,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// UpdateMetadata takes arguments for UpdateMetadataArgs to facilitate the
// updating of metadata fields in Keyfactor. It returns nil upon successful revocation,
// and an error if not. Required fields to update certificate metadata are:
//  - CertID              : int
//  - CertificateMetadata : []CertificateMetadata
func (c *Client) UpdateMetadata(um *UpdateMetadataArgs) error {
	// Metadata in Keyfactor varies between deployments
	// Instead of hard coding possibilities, take array of string tuple types and create
	// string-indexed array of interfaces for JSON compilation
	um.Metadata = mapTupleArrayToInterface(um.CertificateMetadata)

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "PUT",
		Endpoint: "/KeyfactorAPI/Certificates/Metadata",
		Headers:  headers,
		Payload:  um,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// RevokeCert takes arguments for RevokeCertArgs to facilitate the revocation of
// all specified certificate IDs. It returns nil upon successful revocation, and an error if not.
// Required fields to revoke a list of certificates in Keyfactor are:
//  - CertificateIds : []int
//  - Comment        : string
func (c *Client) RevokeCert(ra *RevokeCertArgs) error {
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
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Certificates/Revoke",
		Headers:  headers,
		Payload:  &ra,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// DeployPFXCertificate takes pointers to DeployPFXArgs structs holding
// configuration data required for the deployment of a newly enrolled PFX certificate.
// It returns a pointer to a DeployPFXResp struct if successful, and an error message
// if not. Required fields to deploy a certificate to a store maintained by Keyfactor are:
//  - StoreIds      : []string
//  - Password      : string
//  - CertificateId : int
//  - RequestId     : int
func (c *Client) DeployPFXCertificate(args *DeployPFXArgs) (*DeployPFXResp, error) {
	err := validateDeployPFXArgs(args)
	if err != nil {
		return nil, err
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
		Endpoint: "/KeyfactorAPI/Enrollment/PFX/Deploy",
		Headers:  headers,
		Payload:  &args,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// GetCertificateContext takes arguments for GetCertificateContextArgs used to facilitate the retrieval
// of certificate context. The primary query required to get certificate context is the certificate ID. Include metadata
// and include locations add additional data, but can be set to false if they are unneeded. A pointer to a
// GetCertificateResponse structure is returned, containing the certificate context.
func (c *Client) GetCertificateContext(gca *GetCertificateContextArgs) (*GetCertificateResponse, error) {
	if gca.Id == 0 {
		return nil, errors.New("keyfactor certificate id required to get certificate")
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	// Construct URL query for /Certificates/{ID} requests
	var query *apiQuery
	if gca.IncludeLocations != nil || gca.CollectionId != nil || gca.IncludeMetadata != nil {
		query = &apiQuery{
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

	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: endpoint,
		Headers:  headers,
		Query:    query,
		Payload:  nil,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// RecoverCertificate takes arguments for RecoverCertArgs to facilitate a call to Keyfactor
// that recovers a certificate and associated private key (if retained) in the specified format.
// The download certificate endpoint requires one of the following to retrieve a cert:
//  - CertID
//  - Thumbprint
//  - SerialNumber AND IssuerDN
// Additionally, the certificate Password is required.
func (c *Client) RecoverCertificate(rca *RecoverCertArgs) (*RecoverCertResponse, error) {
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

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", rca.CertFormat},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "/KeyfactorAPI/Certificates/Recover",
		Headers:  headers,
		Payload:  &rca,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
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

// mapTupleArrayToInterface takes an array of StringTuple structs and maps each element to
// a map[string]interface{}
func mapTupleArrayToInterface(i []StringTuple) map[string]interface{} {
	temp := make(map[string]interface{}, len(i)) // Create string-index-able interface array from tuple struct
	for _, field := range i {
		temp[field.Elem1] = field.Elem2
	}
	return temp
}
