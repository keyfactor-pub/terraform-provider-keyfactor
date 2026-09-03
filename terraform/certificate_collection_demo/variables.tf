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

variable "query_override" {
  type        = string
  default     = ""
  description = "Override for the collection query during lab-update testing (full-review finding F3: exercises the content mirror follow-the-driver fix). Empty string means use the default fixed query."
}
