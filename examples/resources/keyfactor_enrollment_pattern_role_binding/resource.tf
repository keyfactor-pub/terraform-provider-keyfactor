resource "keyfactor_enrollment_pattern_role_binding" "example" {
  enrollment_pattern_name = "Web Server Pattern"
  role_name               = "WebServerTerraformer"
}

import {
  to = keyfactor_enrollment_pattern_role_binding.example
  id = "Web Server Pattern//WebServerTerraformer"
}
