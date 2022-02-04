variable "f5_primary_node" {
  description = "Primary F5 node name"
  type        = string
}
variable "f5_primary_node_retry_wait_sec" {
  description = "Time to wait between retries when connecting to primary node"
  type        = string
  default     = "120"
}
variable "f5_primary_node_retry_max" {
  description = "Number of retries allowed when connecting to primary node"
  type        = string
  default     = "3"
}
variable "f5_version" {
  description = "F5 version"
  type        = string
  default     = "v15"
}