package api

type GetTemplateResponse struct {
	Id                     int                        `json:"Id,omitempty"`
	CommonName             string                     `json:"CommonName,omitempty"`
	TemplateName           string                     `json:"TemplateName,omitempty"`
	Oid                    string                     `json:"Oid,omitempty"`
	KeySize                string                     `json:"KeySize,omitempty"`
	KeyType                string                     `json:"KeyType,omitempty"`
	ForestRoot             string                     `json:"ForestRoot,omitempty"`
	FriendlyName           string                     `json:"FriendlyName,omitempty"`
	KeyRetention           string                     `json:"KeyRetention,omitempty"`
	KeyRetentionDays       int                        `json:"KeyRetentionDays,omitempty"`
	KeyArchival            bool                       `json:"KeyArchival,omitempty"`
	EnrollmentFields       []TemplateEnrollmentFields `json:"EnrollmentFields,omitempty"`
	MetadataFields         []TemplateMetadataFields   `json:"MetadataFields,omitempty"`
	AllowedEnrollmentTypes int                        `json:"AllowedEnrollmentTypes,omitempty"`
	TemplateRegexes        []TemplateRegex            `json:"TemplateRegexes,omitempty"`
	UseAllowedRequesters   bool                       `json:"UseAllowedRequesters,omitempty"`
	AllowedRequesters      []string                   `json:"AllowedRequesters,omitempty"`
	RFCEnforcement         bool                       `json:"RFCEnforcement,omitempty"`
	RequiresApproval       bool                       `json:"RequiresApproval,omitempty"`
	KeyUsage               int                        `json:"KeyUsage,omitempty"`
}

type TemplateEnrollmentFields struct {
	Id       int
	Name     string
	Options  []string
	DataType int
}

type TemplateMetadataFields struct {
	Id           int
	DefaultValue string
	MetadataId   int
	Validation   string
	Enrollment   int
	Message      string
	Options      string
}

type TemplateRegex struct {
	TemplateId  int
	SubjectPart string
	RegEx       string
	Error       string
}

type UpdateTemplateArg struct {
	Id                     int                         `json:"Id,omitempty"`
	CommonName             string                      `json:"CommonName,omitempty"`
	TemplateName           string                      `json:"TemplateName,omitempty"`
	Oid                    string                      `json:"Oid,omitempty"`
	KeySize                string                      `json:"KeySize,omitempty"`
	KeyType                *string                     `json:"KeyType,omitempty"`
	ForestRoot             string                      `json:"ForestRoot,omitempty"`
	FriendlyName           *string                     `json:"FriendlyName,omitempty"`
	KeyRetention           *string                     `json:"KeyRetention,omitempty"`
	KeyRetentionDays       *int                        `json:"KeyRetentionDays,omitempty"`
	KeyArchival            *bool                       `json:"KeyArchival,omitempty"`
	EnrollmentFields       *[]TemplateEnrollmentFields `json:"EnrollmentFields,omitempty"`
	MetadataFields         *[]TemplateMetadataFields   `json:"MetadataFields,omitempty"`
	AllowedEnrollmentTypes *int                        `json:"AllowedEnrollmentTypes,omitempty"`
	TemplateRegexes        *[]TemplateRegex            `json:"TemplateRegexes,omitempty"`
	UseAllowedRequesters   *bool                       `json:"UseAllowedRequesters,omitempty"`
	AllowedRequesters      *[]string                   `json:"AllowedRequesters,omitempty"`
	RFCEnforcement         *bool                       `json:"RFCEnforcement,omitempty"`
	RequiresApproval       *bool                       `json:"RequiresApproval,omitempty"`
	KeyUsage               *bool                       `json:"KeyUsage,omitempty"`
}

type UpdateTemplateResponse struct{ GetTemplateResponse }
