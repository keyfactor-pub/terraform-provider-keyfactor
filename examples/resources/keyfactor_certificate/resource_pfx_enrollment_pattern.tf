# Command v25+ style — use certificate_enrollment_pattern instead of certificate_template.
resource "keyfactor_certificate" "pfx_full" {
  # Subject fields
  common_name         = "my.example.com"
  country             = "US"
  state               = "Ohio"
  locality            = "Cleveland"
  organization        = "Acme Corp"
  organizational_unit = "Engineering"

  # SANs
  dns_sans = ["my.example.com", "alt.example.com"]
  ip_sans  = ["192.168.1.10"]
  uri_sans = ["spiffe://cluster.local/ns/default/sa/my-service"]

  # Enrollment method
  # certificate_authority is optional when using an enrollment pattern —
  # Command automatically selects a CA associated with the pattern.
  # Specify it only if you need to pin to a particular CA.
  # certificate_authority          = "MYCA\\My Issuing CA"
  certificate_enrollment_pattern = "2yrWebServer"

  # Key options (omit to accept CA defaults)
  key_type     = "RSA"
  key_size     = 4096
  key_password = "MyStr0ngPassw0rd!"

  # Display / organization
  friendly_name   = "my-cert"
  owner_role_name = "my-role"
  collection_id   = 6

  # Lifecycle
  expiry_warn_days = 90

  renewal_config = {
    renew_days      = 30
    revoke_on_renew = true
    force_renewal   = false
  }

  # Metadata keys must already exist in Keyfactor Command
  metadata = {
    "Email-Contact" = "admin@example.com"
    "Owner"         = "platform-team@example.com"
  }
}
