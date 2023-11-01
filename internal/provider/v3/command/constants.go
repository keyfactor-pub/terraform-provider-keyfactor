package command

const (
	InvalidConfigError             = "Invalid provider configuration."
	InvalidUsernameError           = "`username` and `client_id` cannot both be empty"
	InvalidPasswordError           = "`password` and `client_secret` cannot both be empty"
	InvalidDomainError             = "`domain` was not provided and could not be determined from `username`"
	InvalidHostNameError           = "`hostname` was not provided and could not be determined from `host`"
	DefaultPasswdLength            = 18
	DefaultMinSpecialChar          = 2
	DefaultMinNum                  = 2
	DefaultMinUpperCase            = 2
	CertificateSNFieldName         = "SerialNumber"
	CertificateThumbprintFieldName = "Thumbprint"
	CertificateCNFieldName         = "IssuedCN"
	CertificateDNFieldName         = "IssuedDN"
	CertificateThumbprintLength    = 40
	APICertStateIsCA               = "CertificateAuthority (6)"
	TestCAName                     = "DC-CA.Command.local\\CommandCA1"
)

var ENVIRONMENTAL_VARS = map[string]string{
	"KEYFACTOR_HOSTNAME":              "hostname",
	"KEYFACTOR_APPKEY":                "appkey",
	"KEYFACTOR_PASSWORD":              "password",
	"KEYFACTOR_CERTIFICATE":           "certificate",
	"KEYFACTOR_CLIENT_ID":             "client_id",
	"KEYFACTOR_CLIENT_SECRET":         "client_secret",
	"KEYFACTOR_AUTH_CONFIG":           "auth_config",
	"COMMAND_HOSTNAME":                "hostname",
	"COMMAND_APPKEY":                  "appkey",
	"COMMAND_PASSWORD":                "password",
	"COMMAND_CERTIFICATE":             "certificate",
	"COMMAND_CLIENT_ID":               "client_id",
	"COMMAND_CLIENT_SECRET":           "client_secret",
	"COMMAND_AUTH_CONFIG":             "auth_config",
	"KEYFACTOR_COMMAND_HOSTNAME":      "hostname",
	"KEYFACTOR_COMMAND_APPKEY":        "appkey",
	"KEYFACTOR_COMMAND_PASSWORD":      "password",
	"KEYFACTOR_COMMAND_CERTIFICATE":   "certificate",
	"KEYFACTOR_COMMAND_CLIENT_ID":     "client_id",
	"KEYFACTOR_COMMAND_CLIENT_SECRET": "client_secret",
	"KEYFACTOR_COMMAND_AUTH_CONFIG":   "auth_config",
}
