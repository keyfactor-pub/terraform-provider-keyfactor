# Minimal PFX enrollment — server generates the private key.
# For Command v25+, replace certificate_template with certificate_enrollment_pattern.
resource "keyfactor_certificate" "pfx" {
  common_name           = "my.example.com"
  certificate_authority = "MYCA\\My Issuing CA"
  certificate_template  = "2yrWebServer"
  key_password          = "MyStr0ngPassw0rd!"
}
