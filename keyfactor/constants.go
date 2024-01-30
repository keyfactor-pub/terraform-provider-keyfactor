package keyfactor

const (
	MAX_ITERATIONS                           = 100000
	MAX_WAIT_SECONDS                         = 30
	MAX_APPROVAL_WAIT_LOOPS                  = 5
	SLEEP_DURATION_MULTIPLIER                = 2
	DEFAULT_PFX_PASSWORD_LEN                 = 32
	DEFAULT_PFX_PASSWORD_SPECIAL_CHAR_COUNT  = 4
	DEFAULT_PFX_PASSWORD_NUMBER_COUNT        = 4
	DEFAULT_PFX_PASSWORD_UPPER_COUNT         = 4
	ERR_SUMMARY_INVALID_CERTIFICATE_RESOURCE = "Invalid certificate resource definition."
	ERR_SUMMARY_CERTIFICATE_RESOURCE_CREATE  = "Unable to create Keyfactor Command certificate."
	ERR_SUMMARY_CERTIFICATE_RESOURCE_READ    = "Unable to read Keyfactor Command certificate."
	ERR_SUMMARY_CERT_STORE_READ              = "Unable to read Keyfactor Command certificate store."
	ERR_SUMMARY_AGENT_READ                   = "Unable to read Keyfactor Command agent."
	ERR_SUMMARY_TEMPLATE_READ                = "Unable to read Keyfactor Command template."
	ERR_SUMMARY_IDENTITY_DELETE              = "Unable to delete security identity."
)
