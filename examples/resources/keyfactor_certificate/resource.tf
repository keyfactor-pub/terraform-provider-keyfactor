provider "keyfactor" {
  username = "your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

## PFX Enrollment
resource "keyfactor_certificate" "pkcs12_enrollment" {
  common_name         = "My PKCS12 Certificate"
  country             = "US"
  state               = "Ohio"
  locality            = "Cleveland"
  organization        = "Keyfactor"
  organizational_unit = "Engineering"
  ip_sans             = ["192.168.123.2", "172.51.2.4"]
  dns_sans            = ["My PKCS12 Certificate"]
  uri_sans            = ["my.pkcs12.io"]
  key_password        = "Don't put this in your production code!"
  // Please don't use this password in production pass in an environmental or TF_VAR_ variable.
  certificate_authority = "COMMAND\\MY_CA_01"
  certificate_template  = "2yrWebServer"
  metadata = {
    "Email-Contact" = "kfadmin@keyfactor.com"
  }
}

## CSR Enrollment
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
  certificate_template  = "2yrWebServer"

  dns_sans = ["mycsr.kfdelivery.com"]         # Optional DNS SANs
  ip_sans  = ["172.16.0.2", "192.168.0.2"]    # Optional IP SANs
  uri_sans = ["https://mycsr.kfdelivery.com"] # Optional URI SANs
  metadata = {
    "Email-Contact" = "my_username@mydomain.com"
    # Note: metadata keys must be defined in Keyfactor and cannot just be arbitrarily added
  }
}