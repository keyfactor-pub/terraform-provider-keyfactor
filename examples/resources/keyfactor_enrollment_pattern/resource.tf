resource "keyfactor_enrollment_pattern" "web_server" {
  name             = "Web Server Pattern"
  template_id      = 42
  template_default = true
}

import {
  to = keyfactor_enrollment_pattern.web_server
  id = "Web Server Pattern"
}
