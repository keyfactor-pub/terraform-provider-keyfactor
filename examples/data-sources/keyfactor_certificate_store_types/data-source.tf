# Return all certificate store types
data "keyfactor_certificate_store_types" "all" {}

# Filter by short name prefix
data "keyfactor_certificate_store_types" "k8s" {
  short_name_filter = "K8S"
}

# Filter by capability substring
data "keyfactor_certificate_store_types" "pem_capable" {
  capability_filter = "PEM"
}

# Use results
output "all_short_names" {
  value = data.keyfactor_certificate_store_types.all.store_types[*].short_name
}

output "k8s_store_type_ids" {
  value = data.keyfactor_certificate_store_types.k8s.store_types[*].id
}
