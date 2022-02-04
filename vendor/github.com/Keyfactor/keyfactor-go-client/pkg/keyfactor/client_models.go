package keyfactor

// StringTuple is a struct holding two string elements used by the Keyfactor
// Go Client library for data types requiring a tuple of strings
type StringTuple struct {
	Elem1 string
	Elem2 string
}

// apiHeaders is a struct that holds an array of StringTuples used
// to modularize the passing of custom API headers.
type apiHeaders struct {
	Headers []StringTuple
}

// apiQuery is a struct that holds an array of StringTuples used
// to modularize the passing of custom URL query parameters.
type apiQuery struct {
	Query []StringTuple
}

// request is a structure that holds required information for communicating with
// the Keyfactor API. Included inside this struct is a pointer to an APIHeaders struct, a payload as an
// interface, and other configuration information for the API call.
type request struct {
	Method   string
	Endpoint string
	Headers  *apiHeaders
	Query    *apiQuery
	Payload  interface{}
}
