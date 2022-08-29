package api

type CA struct {
	Id                     int    `json:"Id"`
	LogicalName            string `json:"LogicalName"`
	HostName               string `json:"HostName"`
	Delegate               bool   `json:"Delegate"`
	ForestRoot             string `json:"ForestRoot"`
	Remote                 bool   `json:"Remote"`
	Agent                  string `json:"Agent"`
	Standalone             bool   `json:"Standalone"`
	MonitorThresholds      bool   `json:"MonitorThresholds"`
	IssuanceMax            int    `json:"IssuanceMax"`
	IssuanceMin            int    `json:"IssuanceMin"`
	DenialMax              int    `json:"DenialMax"`
	FailureMax             int    `json:"FailureMax"`
	RFCEnforcement         bool   `json:"RFCEnforcement"`
	Properties             string `json:"Properties"`
	AllowedEnrollmentTypes int    `json:"AllowedEnrollmentTypes"`
	KeyRetention           int    `json:"KeyRetention"`
	KeyRetentionDays       int    `json:"KeyRetentionDays"`
	ExplicitCredentials    bool   `json:"ExplicitCredentials"`
	SubscriberTerms        bool   `json:"SubscriberTerms"`
	ExplicitUser           string `json:"ExplicitUser"`
	ExplicitPassword       struct {
		SecretValue string `json:"SecretValue"`
		Parameters  struct {
		} `json:"Parameters"`
		Provider int `json:"Provider"`
	} `json:"ExplicitPassword"`
	UseAllowedRequesters bool     `json:"UseAllowedRequesters"`
	AllowedRequesters    []string `json:"AllowedRequesters"`
}
