variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to certificate common names to avoid conflicts with existing certificates."
}

variable "certificate_authority" {
  type        = string
  default     = "OpenBao PKI"
  description = "Keyfactor CA logical name. For Windows CAs use \"Host\\\\LogicalName\"; for EJBCA/AnyCA gateways use just the logical name (e.g. \"OpenBao PKI\", the kfclab default)."
}

variable "certificate_template" {
  type        = string
  default     = ""
  description = "Short name of the certificate template to use for enrollment. Mutually exclusive with certificate_enrollment_pattern."
}

variable "certificate_enrollment_pattern" {
  type        = string
  default     = "Lab - AnyCA (lab-role)"
  description = "Name of the enrollment pattern to use (Command v25+ / EJBCA). Mutually exclusive with certificate_template. Defaults to the kfclab lab's pattern; set to \"\" and certificate_template instead for labs without enrollment patterns (pre-v25)."
}

variable "metadata_email" {
  type        = string
  default     = "infosec@example.com"
  description = "Value for the Email-Contact metadata field on the full_csr certificate. kfclab only defines the Email-Contact metadata field (see lab inventory) -- there is no \"Owner\" field on this lab, so this demo no longer sets one (a previous version did, and Command rejected it with \"Invalid Metadata Name: 'Owner'\"). Set to \"\" to omit the metadata block entirely."
}

variable "renew_days" {
  type        = number
  default     = 30
  description = "Trigger automatic renewal when fewer than this many days remain before expiry (full_csr only)."
}
