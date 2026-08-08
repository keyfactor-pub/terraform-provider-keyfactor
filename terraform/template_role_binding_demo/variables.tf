variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to resource names to avoid conflicts."
}

variable "template_short_name" {
  type        = string
  default     = "AnyCA_lab-role"
  description = "An existing certificate template short name to bind the demo role to. Defaults to the kfclab lab's AnyCA_lab-role template; discover others via `make api-list-templates`, override for other labs."
}
