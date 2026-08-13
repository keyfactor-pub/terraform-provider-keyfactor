variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to the PAM provider name to avoid conflicts across runs."
}

variable "vault_host" {
  type        = string
  default     = "https://openbao.lab.local"
  description = "Hostname of the lab's OpenBao/Vault instance."
}

variable "vault_token" {
  type        = string
  sensitive   = true
  default     = null
  description = "Vault token for the PAM provider's secret parameter. No default -- supply via TF_VAR_vault_token. This is a write-only secret parameter; Command never returns it, so it cannot be read back or drift-checked."
}

variable "vault_path_prefix" {
  type        = string
  default     = "secret/kfclab"
  description = "Secret path prefix in Vault/OpenBao for this PAM provider."
}
