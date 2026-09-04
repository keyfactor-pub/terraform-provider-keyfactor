variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to resource names to avoid conflicts."
}

variable "claim_value" {
  type        = string
  default     = "b2c3d4e5-f6a7-4890-bcde-f12345678902"
  description = "The OAuth client ID claim value (a UUID). Used as the claim_value for the OAuthClientId claim."
}

variable "role_description" {
  type        = string
  default     = "Terraform-managed read-only certificate role"
  description = "Description for the OAuth security role."
}

variable "claim_description" {
  type        = string
  default     = "Terraform-managed OAuth client ID claim"
  description = "Description for the OAuth security claim."
}

variable "provider_authentication_scheme" {
  type        = string
  default     = "Authentik"
  description = "The Command OAuth security claim provider authentication scheme. Defaults to Authentik because that is the IdP scheme configured on kfclab; set TF_VAR_provider_authentication_scheme to override for other labs (e.g. \"System\")."
}
