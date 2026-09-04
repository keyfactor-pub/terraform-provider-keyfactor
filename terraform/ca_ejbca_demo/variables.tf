variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to the demo CA's logical_name to avoid collisions across runs."
}

variable "host_name" {
  type        = string
  default     = "https://gateway-gateway-openbao.lab.local/AnyGatewayREST/ejbca"
  description = "AnyCA REST Gateway host URL. Defaults to the kfclab lab's OpenBao gateway (same backend as the lab's real \"OpenBao PKI\" CA, id 2) -- this demo registers a SEPARATE connection record, it does not touch that CA."
}

# ---------------------------------------------------------------------------
# OAuth connector credentials -- NO DEFAULTS. Real, working values for the
# target gateway must be supplied via TF_VAR_ca_client_id /
# TF_VAR_ca_client_secret / TF_VAR_ca_token_url before `apply` (never before
# `validate`, which does not require variable values). Never reuse credentials
# from any archived state snapshot -- those are stale/rotated by design.
# ---------------------------------------------------------------------------
variable "ca_client_id" {
  type        = string
  description = "OAuth client_id for the AnyCA REST Gateway connector. Required at apply time; no default."
  default     = null
}

variable "ca_client_secret" {
  type        = string
  sensitive   = true
  description = "OAuth client_secret for the AnyCA REST Gateway connector. Required at apply time; no default."
  default     = null
}

variable "ca_token_url" {
  type        = string
  description = "OAuth token endpoint URL for the AnyCA REST Gateway connector. Required at apply time; no default. Likely the kfclab Authentik token URL (see ~/.env_kfclab KEYFACTOR_AUTH_TOKEN_URL) if the gateway shares the lab's OAuth provider, or the gateway's own token endpoint if it has one."
  default     = null
}

variable "ca_scope" {
  type        = string
  default     = "ejbca_scope"
  description = "OAuth scope requested for the connector. Changed between apply steps in lab-update to exercise the Update() path."
}

variable "ca_audience" {
  type        = string
  default     = "ejbca_audience"
  description = "OAuth audience requested for the connector. Changed between apply steps in lab-update to exercise the Update() path."
}

variable "force_save" {
  type        = bool
  default     = true
  description = "Bypass Command's connectivity test on create/update. Recommended true while establishing working OAuth credentials for this gateway."
}

variable "monitor_thresholds" {
  type        = bool
  default     = false
  description = "Whether to enable threshold monitoring on the demo CA."
}

variable "issuance_min" {
  type        = number
  default     = 200
  description = "Minimum issuance threshold."
}

variable "issuance_max" {
  type        = number
  default     = 2000
  description = "Maximum issuance threshold."
}

variable "failure_max" {
  type        = number
  default     = 20
  description = "Maximum failure threshold."
}

variable "full_scan_interval_minutes" {
  type        = number
  default     = 120
  description = "Full scan interval, in minutes."
}

variable "incremental_scan_interval_minutes" {
  type        = number
  default     = 15
  description = "Incremental scan interval, in minutes."
}

variable "threshold_check_interval_minutes" {
  type        = number
  default     = 120
  description = "Threshold check interval, in minutes."
}

variable "key_retention" {
  type        = number
  default     = 2
  description = "Key retention policy (0=None, 1=Indefinite, 2=NumberOfDays)."
}

variable "key_retention_days" {
  type        = number
  default     = 180
  description = "Number of days to retain keys when key_retention=2."
}
