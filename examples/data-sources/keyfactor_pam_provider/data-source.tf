# Look up a PAM provider by name
data "keyfactor_pam_provider" "by_name" {
  identifier = "My Thycotic Provider"
}

# Look up a PAM provider by integer ID
data "keyfactor_pam_provider" "by_id" {
  identifier = "1"
}

# Reference a managed provider resource via the data source
resource "keyfactor_pam_provider" "example" {
  name             = "My Provider"
  provider_type_id = "c09bbfa5-a081-4194-9dd2-31f3cc3fabcc"
}

data "keyfactor_pam_provider" "example" {
  identifier = keyfactor_pam_provider.example.name
}

output "provider_type" {
  value = data.keyfactor_pam_provider.example.provider_type_name
}
