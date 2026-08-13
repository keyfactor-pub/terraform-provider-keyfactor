variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to the demo CA's logical_name to avoid collisions across runs."
}

variable "host_name" {
  type        = string
  default     = "fake-tfdemo-schedule-ca.invalid.test"
  description = "Unreachable host name for the demo CA. force_save=true bypasses Command's connectivity test on create/update, so this never needs to resolve."
}

variable "full_scan_interval_minutes" {
  type        = number
  default     = 60
  description = "full_scan_interval_minutes to declare in config. Must be one of the values the schema documents: 1,2,3,4,5,6,10,12,15,20,30,60,120,180,240,360,480,720."
}

variable "incremental_scan_interval_minutes" {
  type        = number
  default     = 15
  description = "incremental_scan_interval_minutes to declare in config. Same allowed-value set as full_scan_interval_minutes."
}

variable "threshold_check_daily_time" {
  type        = string
  default     = null
  description = "Bare UTC time-of-day, formatted \"HH:MM:SS\" (e.g. \"04:15:00\"), for a declarative once-daily threshold_check schedule. Defaults to null, which -- because a `var.x = null` reference produces the same null config value as omitting the attribute entirely -- leaves threshold_check_daily_time genuinely undeclared/unmanaged, same as threshold_check_interval_minutes. Set via TF_VAR_threshold_check_daily_time to exercise the Daily variant declaratively (see GNUmakefile step6-*). A full RFC3339 timestamp is rejected -- Command only preserves the time-of-day component and rewrites the date anchor server-side, so a full timestamp could never round-trip."
}

variable "monitor_thresholds" {
  type        = bool
  default     = false
  description = "Toggled to force an Update() call that does not touch either declared schedule field -- used to prove the undeclared threshold_check_interval_minutes (e.g. set out-of-band) survives verbatim through an unrelated update."
}

variable "auth_certificate_password" {
  type        = string
  default     = "fakepassword"
  description = "Password for the self-signed authcert.pfx (see main.tf and `make authcert`). Some Command instances reject PUT /CertificateAuthority for any HTTPS CA lacking an Authentication Certificate, even under forceSave -- worked around by always declaring a dummy auth cert."
}
