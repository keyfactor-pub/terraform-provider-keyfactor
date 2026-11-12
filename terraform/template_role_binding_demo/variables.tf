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

variable "create_alt_role" {
  type        = bool
  default     = false
  description = "Opt-in (lab-role-replace): also create a second role (keyfactor_role.alt) so role_name can be switched between two real roles. Default false leaves the demo unchanged."
}

variable "binding_role" {
  type        = string
  default     = "primary"
  description = "Opt-in (lab-role-replace): which role the binding's role_name points at, \"primary\" (keyfactor_role.demo) or \"alt\" (keyfactor_role.alt; requires create_alt_role=true). Default \"primary\" leaves the demo unchanged."
  validation {
    condition     = contains(["primary", "alt"], var.binding_role)
    error_message = "binding_role must be \"primary\" or \"alt\"."
  }
}

variable "binding_role_upper" {
  type        = bool
  default     = false
  description = "Opt-in (lab-role-replace): upper-case the binding's role_name to exercise the case-only (in-place, no replacement) change. Default false leaves the demo unchanged."
}
