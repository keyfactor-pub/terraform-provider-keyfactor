# Minimal PFX enrollment using an enrollment pattern (Command v25+).
# certificate_authority is optional — Command automatically selects a CA
# associated with the pattern. Specify it only to pin to a particular CA.
resource "keyfactor_certificate" "pfx_pattern" {
  common_name                    = "my.example.com"
  certificate_enrollment_pattern = "2yrWebServer"
  key_password                   = "MyStr0ngPassw0rd!"
}
