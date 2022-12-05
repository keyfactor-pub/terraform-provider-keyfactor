provider "keyfactor" {
  username = "your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

data "keyfactor_certificate_template" "webserver_template" {
  short_name = "2yrWebServer" #The template shortname of an existing certificate template to reference.
}