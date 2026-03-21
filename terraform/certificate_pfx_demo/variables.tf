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
  description = "Short name of the certificate template to use for enrollment."
}

variable "key_password" {
  type        = string
  default     = "Tftest123456"
  sensitive   = true
  description = "Password used to protect the PKCS#12/PFX output. Required for private key recovery."
}
