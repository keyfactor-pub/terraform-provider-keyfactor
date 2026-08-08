variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to resource common names to avoid conflicts."
}

variable "agent_identifier" {
  type        = string
  default     = "kfclab-uo-secondary-uo"
  description = "GUID or client machine name of an approved, K8S-capable orchestrator agent. Defaults to the kfclab lab's secondary UO."
}

variable "certificate_authority" {
  type        = string
  default     = "OpenBao PKI"
  description = "Keyfactor CA logical name."
}

variable "certificate_template" {
  type        = string
  default     = ""
  description = "Short name of the certificate template to use for enrollment. Mutually exclusive with certificate_enrollment_pattern."
}

variable "certificate_enrollment_pattern" {
  type        = string
  default     = "Lab - AnyCA (lab-role)"
  description = "Name of the enrollment pattern to use (Command v25+). Mutually exclusive with certificate_template."
}

variable "key_password" {
  type        = string
  default     = "Tftest123456"
  sensitive   = true
  description = "Password used to protect the PFX output. Required for private key recovery."
}

variable "namespace" {
  type        = string
  default     = "default"
  description = "Kubernetes namespace to use for store paths."
}

variable "keystore_password" {
  type        = string
  default     = "Tftest123456"
  sensitive   = true
  description = "Password for K8SJKS and K8SPKCS12 keystores."
}

variable "inventory_schedule" {
  type        = string
  default     = "Daily at 12:00:00"
  description = "Inventory schedule applied to all K8S certificate stores. Defaults to a persistent daily schedule to avoid \"immediate\" one-shot drift after apply."
}

variable "create_if_missing" {
  type        = bool
  default     = true
  description = "Whether to schedule a store create job on apply."
}

variable "k8s_server_password_file" {
  type        = string
  default     = ""
  description = "Path to a flat kubeconfig JSON to use as server_password for Keyfactor K8S stores. Leave empty (default) to use kfclab's in-cluster pod-identity auth."
}
