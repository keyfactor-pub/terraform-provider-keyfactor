# Minimal CSR enrollment using an enrollment pattern (Command v25+).
# certificate_authority is optional — Command automatically selects a CA
# associated with the pattern. Specify it only to pin to a particular CA.
resource "tls_private_key" "example_pattern" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "example_pattern" {
  private_key_pem = tls_private_key.example_pattern.private_key_pem
  subject {
    common_name = "my.example.com"
  }
}

resource "keyfactor_certificate" "csr_pattern" {
  csr                            = tls_cert_request.example_pattern.cert_request_pem
  certificate_enrollment_pattern = "2yrWebServer"
}
