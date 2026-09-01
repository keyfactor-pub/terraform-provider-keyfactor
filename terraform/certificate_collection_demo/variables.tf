variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to collection names to avoid conflicts with other lab resources."
}

variable "description_override" {
  type        = string
  default     = ""
  description = "Override for the collection description during lab-update testing."
}
