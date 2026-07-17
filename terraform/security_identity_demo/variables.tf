variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Unused by this demo (keyfactor_identity has no user-settable name field besides account_name), declared only so the GNUmakefile can pass -var=\"suffix=...\" consistently with the other demos in this repo."
}

variable "account_name" {
  type        = string
  default     = "KEYFACTOR\\Administrator"
  description = "AD account name (DOMAIN\\user, HCL-escaped as DOMAIN\\\\user) to register as a Keyfactor security identity. Must exist in Active Directory but not already be a Keyfactor security identity. Override with a real account from an AD-backed lab, e.g. via KEYFACTOR_SECURITY_IDENTITY_NEW-discovered value (see discoverCreatableIdentity in keyfactor/resource_keyfactor_security_identity_test.go)."
}

variable "roles_declared" {
  type        = bool
  default     = true
  description = "Whether to declare the roles attribute in config. Set to false (via -var=\"roles_declared=false\") to omit roles from config entirely and prove PR179's fix preserves existing role assignments across an Update instead of crashing with 'Provider produced inconsistent result after apply'."
}

variable "roles" {
  type        = list(string)
  default     = ["Administrator"]
  description = "Role names to assign when roles_declared is true."
}
