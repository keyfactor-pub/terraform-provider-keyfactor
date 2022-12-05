provider "keyfactor" {
  username = "your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

data "keyfactor_role" "admin" {
  name = "Administrator"
}