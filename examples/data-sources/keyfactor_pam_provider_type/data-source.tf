# Look up a PAM provider type by name
data "keyfactor_pam_provider_type" "by_name" {
  identifier = "Thycotic"
}

# Look up a PAM provider type by GUID
data "keyfactor_pam_provider_type" "by_guid" {
  identifier = "c09bbfa5-a081-4194-9dd2-31f3cc3fabcc"
}

# Use parameter metadata when creating a provider
output "param_ids" {
  value = data.keyfactor_pam_provider_type.by_name.parameters[*].id
}
