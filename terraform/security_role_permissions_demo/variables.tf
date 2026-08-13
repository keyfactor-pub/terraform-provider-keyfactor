variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to resource names to avoid conflicts."
}

variable "role_description" {
  type        = string
  default     = "Terraform-managed role (PR179 permissions-omission-on-update demo)"
  description = "Description for the security role. Changed between apply steps to exercise an unrelated-attribute Update while permissions is omitted."
}

variable "permissions_declared" {
  type        = bool
  default     = true
  description = "Whether to declare the permissions attribute in config. Set to false to omit permissions from config entirely (proves PR179's fix preserves existing permissions across an unrelated Update instead of crashing with 'Provider produced inconsistent result after apply')."
}

variable "permissions" {
  type        = list(string)
  default     = ["Certificates:Read"]
  description = "Permissions to assign when permissions_declared is true."
}
