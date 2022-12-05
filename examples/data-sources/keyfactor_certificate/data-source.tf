provider "keyfactor" {
  username = "your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

data "keyfactor_certificate" "protected_cert" {
  id           = "26"                       #Internal ID of the certificate
  key_password = "my certificate password!" # This is bad practice. Use TF_VAR_<variable_name> instead.
}