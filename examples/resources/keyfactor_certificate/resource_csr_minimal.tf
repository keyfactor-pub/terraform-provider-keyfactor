# Minimal CSR enrollment — the private key never leaves the client.
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "example" {
  private_key_pem = tls_private_key.example.private_key_pem
  subject {
    common_name = "my.example.com"
  }
}

resource "keyfactor_certificate" "csr" {
  csr                   = tls_cert_request.example.cert_request_pem
  certificate_authority = "MYCA\\My Issuing CA"
  certificate_template  = "2yrWebServer"
}
