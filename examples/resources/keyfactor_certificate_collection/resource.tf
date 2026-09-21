resource "keyfactor_certificate_collection" "web_certs" {
  name        = "Web Server Certificates"
  description = "All unexpired web server certificates issued from the internal CA"
  query       = "CertificateTemplate -eq \"2YrWebServer\" AND Status -eq 1"
}

import {
  to = keyfactor_certificate_collection.web_certs
  id = "Web Server Certificates"
}
