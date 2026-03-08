# PAM provider type with string and secret parameters
resource "keyfactor_pam_provider_type" "example" {
  name = "My Custom PAM Type"

  parameters = [
    {
      name           = "Hostname"
      display_name   = "PAM Server Hostname"
      data_type      = 1 # string
      instance_level = false
    },
    {
      name           = "Password"
      display_name   = "PAM Account Password"
      data_type      = 2 # secret
      instance_level = false
    },
  ]
}

# Minimal PAM provider type with no parameters
resource "keyfactor_pam_provider_type" "minimal" {
  name = "My Minimal PAM Type"
}
