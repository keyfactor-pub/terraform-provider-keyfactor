# Look up an existing PAM provider type to get its parameter IDs
data "keyfactor_pam_provider_type" "thycotic" {
  identifier = "Thycotic"
}

# PAM provider using a known provider type GUID and parameter IDs
resource "keyfactor_pam_provider" "example" {
  name             = "My Thycotic Provider"
  provider_type_id = data.keyfactor_pam_provider_type.thycotic.id

  param_values = [
    {
      param_id = data.keyfactor_pam_provider_type.thycotic.parameters[0].id
      name     = data.keyfactor_pam_provider_type.thycotic.parameters[0].name
      value    = "https://thycotic.example.com"
    },
    {
      param_id = data.keyfactor_pam_provider_type.thycotic.parameters[1].id
      name     = data.keyfactor_pam_provider_type.thycotic.parameters[1].name
      value    = var.thycotic_secret_key # sensitive — never shown in plan output
    },
  ]
}

# PAM provider with no parameter values (all defaults)
resource "keyfactor_pam_provider" "minimal" {
  name             = "My Minimal Provider"
  provider_type_id = "c09bbfa5-a081-4194-9dd2-31f3cc3fabcc"
}
