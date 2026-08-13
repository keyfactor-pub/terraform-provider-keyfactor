variable "representative_store_type" {
  type        = string
  default     = "K8STLSSecr"
  description = "Short name or integer ID of one store type to look up via the singular data.keyfactor_certificate_store_type data source."
}
