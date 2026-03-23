variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to certificate common names to avoid conflicts with existing certificates."
}

variable "certificate_authority" {
  type        = string
  description = "Keyfactor CA logical name. For Windows CAs use \"Host\\\\LogicalName\"; for EJBCA use just the logical name (e.g. \"Sub-CA\")."
}

variable "certificate_template" {
  type        = string
  default     = ""
  description = "Short name of the certificate template to use for enrollment. Mutually exclusive with certificate_enrollment_pattern."
}

variable "certificate_enrollment_pattern" {
  type        = string
  default     = ""
  description = "Name of the enrollment pattern to use (Command v25+ / EJBCA). Mutually exclusive with certificate_template."
}
