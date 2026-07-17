variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to resource names to avoid conflicts."
}

variable "role_description" {
  type        = string
  default     = "Terraform-managed read-only certificate role (PR178 drift-detection demo)"
  description = "Description for the security role."
}
