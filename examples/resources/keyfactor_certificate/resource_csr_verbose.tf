# Full CSR enrollment with all subject fields and optional settings.
# certificate_template is the pre-v25 style; for Command v25+ use:
#   certificate_enrollment_pattern = "2yrWebServer"
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

  # Enrollment method (pre-v25 template style)
  certificate_authority = "MYCA\\My Issuing CA"
  certificate_template  = "2yrWebServer"
  # certificate_enrollment_pattern = "2yrWebServer"  # v25+ alternative

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
