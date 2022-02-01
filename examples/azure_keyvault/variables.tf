variable "az_tenant_id" {
    description = "Tenant ID of Azure instance"
    type = string
}
variable "az_resource_group_name" {
    description = "Azure resource group name"
    type = string
}
variable "az_application_id" {
    description = "Application ID of vault"
    type = string
}
variable "az_client_secret" {
    description = "Client secret associated with service principal"
    type = string
}
variable "az_subscription_id" {
    description = "Subscription ID associated with Azure tenant"
    type = string
}

variable "az_app_object_id" {
    description = "Object ID associated with service principal"
    type = string
}

variable "az_vault_name" {
    description = "Name of Azure key vault"
    type = string
}