provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

## PFX Enrollment
resource "keyfactor_certificate" "pfx_cert" {
  subject = {
    subject_common_name = "ShortlivedTest7622-test"
  }
  dns_sans = ["ShortlivedTest7622-test"]

  key_password          = "don't put secrets in code!" // Please don't use this password in production pass in an environmental variable or something
  certificate_authority = "<test_domain>\\<test_ca>"
  certificate_template  = "<my_template>"
}

# Deploy the created PFX certificate to all created cert stores
resource "keyfactor_certificate_deployment" "pfx_cert" {
  certificate_id       = keyfactor_certificate.pfx_cert.id # ID of the certificate to deploy
  certificate_store_id = "<my_certstore_id>"               # ID of the certificate store to deploy to
  certificate_alias    = "<my_cert_alias>"                 # Alias to use for the certificate in the store
}

