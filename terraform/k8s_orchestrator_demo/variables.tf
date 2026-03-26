variable "k8s_credentials_file" {
  type        = string
  description = "Path to the standard kubeconfig file used by the kubernetes provider. Must be set via TF_VAR_k8s_credentials_file or passed explicitly."
  default     = null
}

variable "k8s_server_password_file" {
  type        = string
  description = "Path to the flat kubeconfig JSON used as server_password for Keyfactor K8S stores. Defaults to sa-context.json symlink in this directory."
  default     = null
}

variable "namespace" {
  type        = string
  description = "Kubernetes namespace to use for store paths."
  default     = "default"
}

variable "keystore_password" {
  type        = string
  description = "Password for K8SJKS and K8SPKCS12 keystores (required by Command)."
  default     = "Tftest123456"
  sensitive   = true
}

variable "inventory_schedule" {
  type    = string
  default = "immediate"
  description = <<-EOT
    Inventory schedule applied to all K8S certificate stores.

    Accepted formats:
      "immediate"          — trigger inventory on next orchestrator check-in (one-shot)
      "Nm"                 — every N minutes (e.g. "30m")
      "Nh"                 — every N hours, N < 24 (e.g. "6h")
      "Daily at HH:MM:SS"  — once per day at the specified UTC time (e.g. "Daily at 12:00:00")

    CAVEAT — "immediate" drift: Command treats "immediate" as a one-shot trigger.
    Once the inventory job runs successfully (or exhausts retries) Command removes the
    schedule, so the next `terraform plan` will show the store drifting from "immediate"
    to an empty/daily schedule. This is expected behaviour.  Use a persistent schedule
    (e.g. "Daily at 12:00:00") to avoid perpetual drift after the first apply.
  EOT
}

variable "create_if_missing" {
  type        = bool
  description = "Whether to schedule a store create job on apply. Set to true to auto-create the backing K8S secret if it does not exist."
  default     = true
}

# ---------------------------------------------------------------------------
# Certificate enrollment variables
# ---------------------------------------------------------------------------

variable "certificate_authority" {
  type        = string
  description = "Keyfactor CA logical name. For Windows CAs use \"Host\\\\LogicalName\"; for EJBCA use just the logical name (e.g. \"Sub-CA\")."
}

variable "certificate_template" {
  type        = string
  default     = ""
  description = "Short name of the certificate template to use for enrollment. Mutually exclusive with certificate_enrollment_pattern."
}

variable "certificate_enrollment_pattern" {
  type        = string
  default     = ""
  description = "Name of the enrollment pattern to use (Command v25+ / EJBCA). Mutually exclusive with certificate_template."
}

variable "key_password" {
  type        = string
  default     = "Tftest123456"
  sensitive   = true
  description = "Password used to protect the PKCS#12/PFX output. Required for private key recovery."
}
