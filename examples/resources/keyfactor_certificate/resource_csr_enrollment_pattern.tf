# Command v25+ style — use certificate_enrollment_pattern instead of certificate_template.
resource "tls_private_key" "csr_full" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "csr_full" {
  private_key_pem = tls_private_key.csr_full.private_key_pem

  subject {
    common_name         = "my.example.com"
    organization        = "Acme Corp"
    country             = "US"
    locality            = "Cleveland"
    organizational_unit = "Engineering"
    province            = "Ohio"
    street_address      = "123 Main St"
  }
}

resource "keyfactor_certificate" "csr_full" {
  csr = tls_cert_request.csr_full.cert_request_pem

  # Enrollment method
  # certificate_authority is optional when using an enrollment pattern —
  # Command automatically selects a CA associated with the pattern.
  # Specify it only if you need to pin to a particular CA.
  # certificate_authority          = "MYCA\\My Issuing CA"
  certificate_enrollment_pattern = "2yrWebServer"

  # Display / organization
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
