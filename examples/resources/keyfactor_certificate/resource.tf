# PFX Enrollment
resource "keyfactor_certificate" "pkcs12_enrollment" {
  common_name           = "My PKCS12 Certificate"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Keyfactor"
  organizational_unit   = "Engineering"
  ip_sans               = sort(["192.168.123.2", "172.51.2.4"])
  dns_sans              = sort(["my.pkcs12.io", "My PKCS12 Certificate", "my.pkcs12.co.uk", "Certificate PKCS12 My"])
  uri_sans              = sort(["my.pkcs12.io"])
  key_password          = "Don't put this in your production code!"
  certificate_authority = "COMMAND\\MY_CA_01"
  # certificate_template  = "2yrWebServer" // Deprecated as of Keyfactor 25.x in favor of certificate_enrollment_pattern
  certificate_enrollment_pattern = "2yrWebServer"
  metadata = {
    "Email-Contact" = "kfadmin@keyfactor.com"
    "Owner"         = "integrations@keyfactor.com"
  }

  owner_role_name = "integrations"

  friendly_name = "friend"
  collection_id = 6

  expiry_warn_days = 90

  renewal_config = {
    renew_days      = 30
    revoke_on_renew = true
    force_renewal   = false
  }
}

# CSR Enrollment
resource "tls_private_key" "rsa_4096" {
  # Create a private key for the certificate request.
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "csr" {
  # Create a CSR using the TLS private key above
  private_key_pem = tls_private_key.rsa_4096.private_key_pem

  subject {
    common_name         = "mycsr.kfdelivery.com"
    organization        = "Keyfactor"
    country             = "US"
    locality            = "Seattle"
    organizational_unit = "DevOps Enablement"
    postal_code         = "12345"
    province            = "WA"
    street_address      = ["123 Main St", "Suite 1", "Second Floor", "Downtown"]
  }
}

resource "keyfactor_certificate" "kf_csr_cert" {
  csr                   = tls_cert_request.csr.cert_request_pem
  certificate_authority = "COMMAND\\MY_CA_01"
  # certificate_template  = "2yrWebServer" // Deprecated as of Keyfactor 25.x in favor of certificate_enrollment_pattern
  certificate_enrollment_pattern = "2yrWebServer"
  metadata = {
    "Email-Contact" = "my_username@mydomain.com"
    # Note: metadata keys must be defined in Keyfactor and cannot just be arbitrarily added
  }

  owner_role_name = "my_role_name"

  collection_id = 2

  expiry_warn_days = 90

  renewal_config = {
    renew_days      = 30
    revoke_on_renew = true
    force_renewal   = false
  }
}