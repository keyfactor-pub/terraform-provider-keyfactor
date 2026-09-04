variable "suffix" {
  type        = string
  description = "Suffix appended to the application name to avoid collisions across test runs."
  default     = "_TF"
}

variable "namespace" {
  type        = string
  description = "Kubernetes namespace to use for store paths."
  default     = "default"
}

variable "inventory_schedule" {
  type        = string
  default     = "Daily at 12:00:00"
  description = <<-EOT
    Inventory schedule applied to all K8S certificate stores.

    Accepted formats:
      "immediate"          — trigger inventory on next orchestrator check-in (one-shot)
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

variable "k8s_server_password_file" {
  type        = string
  description = "Path to a flat kubeconfig JSON to use as server_password for Keyfactor K8S stores. Leave empty (default) to use kfclab's in-cluster pod-identity auth (server_username=\"kubeconfig\", no password)."
  default     = ""
}

# ---------------------------------------------------------------------------
# Issue #175 reproduction — container-clearing-on-unrelated-update.
# See repro175.tf for the resource and the GNUmakefile's repro175-* targets
# for the seed/verify sequence.
# ---------------------------------------------------------------------------
variable "repro175_inventory_schedule" {
  type        = string
  default     = "Daily at 13:00:00"
  description = "Inventory schedule for the repro175 store. Changed between repro175-seed and repro175-verify-apply to force an unrelated Update() call without ever declaring container_name/application_name in config."
}
