package keyfactor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// APIClient is a struct holding all necessary client configuration data
// for communicating with the Keyfactor API. This includes the hostname,
// username, password, and domain.
type APIClient struct {
	Hostname string
	Username string
	Password string
	Domain   string
}

// StringTuple is a struct holding two string elements used by the Keyfactor
// Go Client library for data types requiring a tuple of strings
type StringTuple struct {
	Elem1 string
	Elem2 string
}

// APIHeaders is a struct that holds an array of StringTuples used
// to modularize the passing of custom API headers.
type APIHeaders struct {
	Headers []StringTuple
}

// APIQuery is a struct that holds an array of StringTuples used
// to modularize the passing of custom URL query parameters.
type APIQuery struct {
	Query []StringTuple
}

// APIRequest is a structure that holds required information for communicating with
// the Keyfactor API. Included inside this struct is a pointer to an APIClient struct,
// a pointer to an APIHeaders struct, a payload as an unstructured interface, and other
// configuration information for the API call.
type APIRequest struct {
	KFClient *APIClient
	Method   string
	Endpoint string
	Headers  *APIHeaders
	Query    *APIQuery
	Payload  interface{}
}

// SendRequest takes an APIRequest struct as input and generates an API call
// using the configuration data inside. It returns a pointer to an http response
// struct and an error, if applicable.
func SendRequest(request *APIRequest) (*http.Response, error) {
	kfApiClientData := request.KFClient // Extract Keyfactor client data

	u, err := url.Parse(kfApiClientData.Hostname) // Parse raw hostname into URL structure
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		u.Scheme = "https"
	}
	u.Path = path.Join(u.Path, request.Endpoint) // Attach enroll endpoint

	// Set request query
	if request.Query != nil {
		queryString := u.Query()
		for _, query := range request.Query.Query {
			queryString.Set(query.Elem1, query.Elem2)
		}
		u.RawQuery = queryString.Encode()
	}

	keyfactorPath := u.String() // Convert absolute path to string

	log.Printf("[INFO] Preparing a %s request to path '%s'", request.Method, keyfactorPath)
	jsonByes, err := json.Marshal(request.Payload)
	if err != nil {
		return nil, err
	}
	log.Printf("[INFO] Request body: %s", jsonByes)

	req, err := http.NewRequest(request.Method, keyfactorPath, bytes.NewBuffer(jsonByes))
	if err != nil {
		return nil, err
	}

	authField := buildAuthField(request.KFClient)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", authField)

	// Set custom Keyfactor headers
	for _, headers := range request.Headers.Headers {
		req.Header.Set(headers.Elem1, headers.Elem2)
	}

	log.Println("[TRACE] Executing request with client.Do")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// buildAuthField takes an APIClient struct as input and returns a base-64 encoded
// Basic authorization field required for communication with the Keyfactor API.
func buildAuthField(creds *APIClient) string {
	var authString string
	log.Println("[TRACE] Building Authorization field")
	if creds.Domain == "" {
		authString = strings.Join([]string{creds.Username, ":", creds.Password}, "")
	} else {
		authString = strings.Join([]string{creds.Domain, "\\", creds.Username, ":", creds.Password}, "")
	}
	authBytes := []byte(authString)
	authDigest := base64.StdEncoding.EncodeToString(authBytes)
	authField := strings.Join([]string{"Basic ", authDigest}, "")
	return authField
}

func getTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
