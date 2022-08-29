package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Client struct {
	hostname        string
	httpClient      *http.Client
	basicAuthString string
}

// AuthConfig is a struct holding all necessary client configuration data
// for communicating with the Keyfactor API. This includes the hostname,
// username, password, and domain.
type AuthConfig struct {
	Hostname string
	Username string
	Password string
	Domain   string
}

// NewKeyfactorClient creates a new Keyfactor client instance. A configured Client is returned with methods used to
// interact with Keyfactor.
func NewKeyfactorClient(auth *AuthConfig) (*Client, error) {
	c, err := loginToKeyfactor(auth)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// validateAuthConfig ensures that the required fields for the creation of a new Keyfactor client struct were passed
// to the NewKeyfactorClient method. In the future, this method will be updated to ask Keyfactor for session token.
func loginToKeyfactor(auth *AuthConfig) (*Client, error) {
	if auth.Hostname == "" {
		return nil, errors.New("keyfactor hostname required for creation of new client")
	}
	if auth.Username == "" {
		return nil, errors.New("keyfactor username required for creation of new client")
	}
	if auth.Password == "" {
		return nil, errors.New("keyfactor password required for creation of new client")
	}

	headers := &apiHeaders{
		Headers: []StringTuple{
			{"x-keyfactor-api-version", "1"},
			{"x-keyfactor-requested-with", "APIClient"},
		},
	}

	keyfactorAPIStruct := &request{
		Method:   "GET",
		Endpoint: "Status/Endpoints",
		Headers:  headers,
	}

	c := &Client{
		hostname:        auth.Hostname,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		basicAuthString: buildBasicAuthString(auth),
	}

	_, err := c.sendRequest(keyfactorAPIStruct)
	if err != nil {
		return nil, err
	}

	log.Printf("[INFO] Successfully logged into Keyfactor at host %s", c.hostname)

	return c, nil
}

// SendRequest takes an APIRequest struct as input and generates an API call
// using the configuration data inside. It returns a pointer to an http response
// struct and an error, if applicable.
func (c *Client) sendRequest(request *request) (*http.Response, error) {
	u, err := url.Parse(c.hostname) // Parse raw hostname into URL structure
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		u.Scheme = "https"
	}
	endpoint := "KeyfactorAPI/" + request.Endpoint
	u.Path = path.Join(u.Path, endpoint) // Attach enroll endpoint

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
	log.Printf("[TRACE] Request body: %s", jsonByes)

	req, reqErr := http.NewRequest(request.Method, keyfactorPath, bytes.NewBuffer(jsonByes))
	if reqErr != nil {
		return nil, reqErr
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.basicAuthString)

	// Set custom Keyfactor headers
	for _, headers := range request.Headers.Headers {
		req.Header.Set(headers.Elem1, headers.Elem2)
	}

	resp, respErr := c.httpClient.Do(req)
	if respErr != nil {
		return nil, respErr
	}
	var stringMessage string
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		log.Printf("[DEBUG] %s succeeded with response code %d", request.Method, resp.StatusCode)
		return resp, nil
	} else if resp.StatusCode == http.StatusNotFound {

		var errorMessage interface{} // Decode JSON body to handle issue
		// First, try to serialize the response into an interface, but catch the exception.
		defer func() {
			if nfErr := recover(); nfErr != nil {
				stringMessage = "404 - file or directory not found"
			}
		}()
		err = json.NewDecoder(resp.Body).Decode(&errorMessage)
		if err != nil {
			return nil, err
		}
		stringMessage = fmt.Sprintf("%v", errorMessage)
		log.Printf("[ERROR] Call to %s returned status %d. %s", keyfactorPath, resp.StatusCode, stringMessage)
		return nil, errors.New(stringMessage)
	} else {
		var errorMessage interface{} // Decode JSON body to handle issue
		err = json.NewDecoder(resp.Body).Decode(&errorMessage)
		if err != nil {
			return nil, err
		}

		log.Printf("[DEBUG] Request failed with code %d and message %v", resp.StatusCode, errorMessage)
		stringMessage = fmt.Sprintf("%v", errorMessage)
		return nil, errors.New(stringMessage)
	}
}

// buildBasicAuthString constructs a basic authorization string necessary for basic authorization to Keyfactor. It
// returns a base-64 encoded auth string including the 'Basic ' prefix.
func buildBasicAuthString(auth *AuthConfig) string {
	var authString string
	log.Println("[TRACE] Building Authorization field")
	if auth.Domain == "" {
		authString = strings.Join([]string{auth.Username, ":", auth.Password}, "")
	} else {
		authString = strings.Join([]string{auth.Domain, "\\", auth.Username, ":", auth.Password}, "")
	}
	authBytes := []byte(authString)
	authDigest := base64.StdEncoding.EncodeToString(authBytes)
	authField := strings.Join([]string{"Basic ", authDigest}, "")
	return authField
}

func getTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
