# Minimal store type — only name and short_name required
resource "keyfactor_certificate_store_type" "minimal" {
  name       = "My PEM Store Type"
  short_name = "MyPEM"

  private_key_allowed  = "Optional"
  custom_alias_allowed = "Forbidden"
  supports_add         = true
  supports_remove      = true
}

# Store type with property and entry-parameter definitions
resource "keyfactor_certificate_store_type" "example" {
  name       = "My Custom Store Type"
  short_name = "MyCSTv1"

  private_key_allowed  = "Optional"
  custom_alias_allowed = "Forbidden"
  server_required      = true

  supports_add        = true
  supports_remove     = true
  supports_create     = false
  supports_discovery  = false
  supports_enrollment = false

  password_entry_supported = false
  password_store_required  = false
  password_style           = "Default"

  properties = [
    {
      name         = "LinuxFilePermissionsOnStoreCreation"
      display_name = "Linux File Permissions on Store Creation"
      type         = "String"
      required     = false
      default_value = "600"
    },
  ]

  entry_parameters = [
    {
      name                          = "Alias"
      display_name                  = "Certificate Alias"
      type                          = "String"
      required_when_on_add          = true
      required_when_on_remove       = false
      required_when_has_private_key = false
      required_when_on_reenrollment = false
    },
  ]
}
