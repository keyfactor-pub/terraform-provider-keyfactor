variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to resource names to avoid conflicts."
}

variable "template_short_name" {
  type        = string
  default     = "Server_tlsServerAuth-1y"
  description = "An existing certificate template short name with UseAllowedRequesters already enabled, to bind the demo role to. Discovered via `make api-list-templates` against int25-4-1.kftestlab.com; override for other labs."
}
