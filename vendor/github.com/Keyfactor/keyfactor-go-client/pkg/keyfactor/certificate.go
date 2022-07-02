package keyfactor

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go.mozilla.org/pkcs7"
	"log"
	"net/http"
	"software.sslmate.com/src/go-pkcs12"
	"strconv"
	"strings"
)

// EnrollPFX takes arguments for EnrollPFXFctArgs to facilitate a call to Keyfactor
// that enrolls a PFX certificate with the supplied arguments.
func (c *Client) EnrollPFX(ea *EnrollPFXFctArgs) (*EnrollResponse, error) {
	log.Println("[INFO] Enrolling PFX certificate with Keyfactor")

	/* Ensure required inputs exist */
	if (ea.Template == "") || (ea.Password == "") || (ea.CertificateAuthority == "") || (ea.CertFormat == "") {
		return nil, errors.New("invalid or nonexistent values required for pfx enrollment")
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", ea.CertFormat},
		},
	}

	if ea.Timestamp == "" {
		ea.Timestamp = getTimestamp()
	}

	if ea.SubjectString == "" {
		if ea.Subject != nil {
			subject, err := createSubject(*ea.Subject)
			if err != nil {
				return nil, err
			}
			ea.SubjectString = subject
		} else {
			return nil, fmt.Errorf("subject is required to use enrollpfx(). Please configure either SubjectString or Subject")
		}
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "Enrollment/PFX",
		Headers:  headers,
		Payload:  &ea,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

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

// DownloadCertificate takes arguments for DownloadCertArgs to facilitate a call to Keyfactor
// that downloads a certificate from Keyfactor.
// The download certificate endpoint requires one of the following to retrieve a cert:
//  - CertID
//  - Thumbprint
//  - SerialNumber AND IssuerDN
// Returns:
//   - Leaf certificate
//   - Certificate chain
func (c *Client) DownloadCertificate(certId int, thumbprint string, serialNumber string, issuerDn string) (*x509.Certificate, []*x509.Certificate, error) {
	log.Println("[INFO] Downloading certificate")

	/* The download certificate endpoint requires one of the following to retrieve a cert:
		- CertID
		- Thumbprint
		- SerialNumber AND IssuerDN

	Check for this input
	*/
	validInput := false
	if certId != 0 {
		validInput = true
	} else if thumbprint != "" {
		validInput = true
	} else if serialNumber != "" && issuerDn != "" {
		validInput = true
	}

	if !validInput {
		return nil, nil, fmt.Errorf("certID, thumbprint, or serial number AND issuer DN required to dowload certificate")
	}

	payload := &downloadCertificateBody{
		CertID:       certId,
		SerialNumber: serialNumber,
		IssuerDN:     issuerDn,
		Thumbprint:   thumbprint,
		IncludeChain: true,
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", "P7B"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "Certificates/Download",
		Headers:  headers,
		Payload:  &payload,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, nil, err
	}

	jsonResp := &downloadCertificateResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, nil, err
	}
	buf, err := base64.StdEncoding.DecodeString(jsonResp.Content)
	if err != nil {
		return nil, nil, err
	}

	certs, err := pkcs7.Parse(buf)
	if err != nil {
		return nil, nil, err
	}

	leaf := certs.Certificates[0]

	if len(certs.Certificates) > 1 {
		return leaf, certs.Certificates[1:], nil
	}

	return leaf, nil, nil
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

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", ea.CertFormat},
		},
	}

	if ea.Timestamp == "" {
		ea.Timestamp = getTimestamp()
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "Enrollment/CSR",
		Headers:  headers,
		Payload:  &ea,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	jsonResp := &EnrollResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	jsonResp.Certificates = jsonResp.CertificateInformation.Certificates
	return jsonResp, nil
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
		Endpoint: "Certificates/Revoke",
		Headers:  headers,
		Payload:  &ra,
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
		Endpoint: "Enrollment/PFX/Deploy",
		Headers:  headers,
		Payload:  &args,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	jsonResp := &DeployPFXResp{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, nil
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

	endpoint := "Certificates/" + fmt.Sprintf("%d", gca.Id) // Append ID to complete endpoint

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

	jsonResp := &GetCertificateResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, err
	}
	return jsonResp, err
}

// RecoverCertificate takes arguments for RecoverCertArgs to facilitate a call to Keyfactor
// that recovers a certificate and associated private key (if retained) in the specified format.
// The download certificate endpoint requires one of the following to retrieve a cert:
//  - CertID
//  - Thumbprint
//  - SerialNumber AND IssuerDN
// Additionally, the certificate Password is required.
// Returns:
//   - Private key (*rsa.PrivateKey or *ecdsa.PrivateKey)
//   - Leaf certificate (*x509.Certificate)
//   - Certificate chain ([]*x509.Certificate)
func (c *Client) RecoverCertificate(certId int, thumbprint string, serialNumber string, issuerDn string, password string) (interface{}, *x509.Certificate, []*x509.Certificate, error) {
	log.Println("[INFO] Recovering certificate")
	/* The download certificate endpoint requires one of the following to retrieve a cert:
		- CertID
		- Thumbprint
		- SerialNumber AND IssuerDN

	Check for this input
	*/
	validInput := false
	if certId != 0 {
		validInput = true
	} else if thumbprint != "" {
		validInput = true
	} else if serialNumber != "" && issuerDn != "" {
		validInput = true
	}

	if !validInput {
		return nil, nil, nil, fmt.Errorf("certID, thumbprint, or serial number AND issuer DN required to dowload certificate")
	}

	if password == "" {
		return nil, nil, nil, fmt.Errorf("password required to recover private key with certificate")
	}

	rca := &recoverCertArgs{
		CertId:       certId,
		Password:     password,
		SerialNumber: serialNumber,
		IssuerDN:     issuerDn,
		Thumbprint:   thumbprint,
		IncludeChain: true,
	}

	// Set Keyfactor-specific headers
	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
			{"x-certificateformat", "PFX"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "POST",
		Endpoint: "Certificates/Recover",
		Headers:  headers,
		Payload:  &rca,
	}

	resp, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, nil, nil, err
	}

	jsonResp := &recoverCertResponse{}
	err = json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err != nil {
		return nil, nil, nil, err
	}

	pfxDer, err := base64.StdEncoding.DecodeString(jsonResp.PFX)

	priv, leaf, chain, err := pkcs12.DecodeChain(pfxDer, rca.Password)
	if err != nil {
		return nil, nil, nil, err
	}

	return priv, leaf, chain, nil
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
