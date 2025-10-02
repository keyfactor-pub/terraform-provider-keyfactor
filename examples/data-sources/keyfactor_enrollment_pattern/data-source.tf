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