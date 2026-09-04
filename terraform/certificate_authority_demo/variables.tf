variable "logical_name" {
  type        = string
  default     = "OpenBao PKI"
  description = "Logical name of the existing lab CA to import (see `make api-list-cas-short`)."
}

variable "host_name" {
  type        = string
  default     = "https://gateway-gateway-openbao.lab.local/AnyGatewayREST/ejbca"
  description = "Host name of the existing lab CA to import."
}

variable "ca_type" {
  type        = number
  default     = 1
  description = "CA type of the existing lab CA to import (0=DCOM, 1=HTTPS/EJBCA)."
}
