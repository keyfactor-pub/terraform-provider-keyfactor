variable "logical_name" {
  type        = string
  default     = "Sub-CA"
  description = "Logical name of the existing lab CA to import (see `make api-list-cas-short`)."
}

variable "host_name" {
  type        = string
  default     = "http://ejbca-ca.int25-4-1.svc.cluster.local:8082/ejbca"
  description = "Host name of the existing lab CA to import."
}

variable "ca_type" {
  type        = number
  default     = 1
  description = "CA type of the existing lab CA to import (0=DCOM, 1=HTTPS/EJBCA)."
}
