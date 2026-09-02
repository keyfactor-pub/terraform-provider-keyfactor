variable "template_name" {
  type        = string
  default     = "AnyCA_lab-role"
  description = "Common name, display name, or integer ID of an existing certificate template to associate the demo enrollment pattern with. Defaults to the kfclab lab's AnyCA_lab-role template."
}

variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to the enrollment pattern name to avoid conflicts with other lab resources."
}

variable "description_override" {
  type        = string
  default     = ""
  description = "Override for the enrollment pattern description during lab-update testing."
}
