provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

# Fetch enrollment pattern based on internal ID (integer)
data "keyfactor_enrollment_pattern" "ep_10" {
  identifier = "10"
}

# Fetch enrollment pattern based on name
data "keyfactor_enrollment_pattern" "ep_2yrTest" {
  identifier = "2YrTestWebServer (2YrTestWebServer)"
}

# Fetch enrollment pattern by template short name (works when exactly one pattern exists for the template)
data "keyfactor_enrollment_pattern" "by_template" {
  template_short_name = "WebServer"
}

# Fetch the DEFAULT enrollment pattern for a template (use when multiple patterns share the same template)
data "keyfactor_enrollment_pattern" "by_template_default" {
  template_short_name = "WebServer"
  template_default    = true
}

# Fetch a NON-DEFAULT enrollment pattern for a template
data "keyfactor_enrollment_pattern" "by_template_non_default" {
  template_short_name = "WebServer"
  template_default    = false
}
