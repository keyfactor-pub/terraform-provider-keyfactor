# Look up a certificate store type by short name
data "keyfactor_certificate_store_type" "by_name" {
  identifier = "K8STLSSecr"
}

# Look up a certificate store type by numeric ID
data "keyfactor_certificate_store_type" "by_id" {
  identifier = "109"
}

# Reference computed attributes
output "store_type_id" {
  value = data.keyfactor_certificate_store_type.by_name.id
}

output "supports_add" {
  value = data.keyfactor_certificate_store_type.by_name.supports_add
}

output "properties" {
  value = data.keyfactor_certificate_store_type.by_name.properties
}
