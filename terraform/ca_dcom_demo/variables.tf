variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to the demo CA's logical_name to avoid collisions across runs."
}

variable "host_name" {
  type        = string
  default     = "fake-dcom-ca.example.lab"
  description = "Fictitious AD CS host name. Deliberately fake/unreachable -- this lab has no real DCOM CA backend; see main.tf header."
}

variable "forest_root" {
  type        = string
  default     = "example.lab"
  description = "Fictitious AD forest root / configuration tenant. Deliberately fake -- this lab has no real Active Directory."
}
