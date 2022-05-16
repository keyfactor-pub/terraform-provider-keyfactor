package keyfactor

// UpdateMetadataArgs holds the function arguments used for calling the UpdateMetadata method.
type UpdateMetadataArgs struct {
	CertID              int                    `json:"Id"`
	CertificateMetadata []StringTuple          `json:"-"`
	Metadata            map[string]interface{} `json:"Metadata"`
	CollectionId        int                    `json:"CollectionId"`
}

type MetadataField struct {
	Id           int    `json:"Id"`
	Name         string `json:"Name"`
	Description  string `json:"Description"`
	DataType     int    `json:"DataType"`
	Hint         string `json:"Hint"`
	Validation   string `json:"Validation"`
	Enrollment   int    `json:"Enrollment"`
	Message      string `json:"Message"`
	Options      string `json:"Options"`
	DefaultValue string `json:"DefaultValue"`
	DisplayOrder int    `json:"DisplayOrder"`
}
