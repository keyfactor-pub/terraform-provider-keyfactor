provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

resource "keyfactor_security_identity" "identity" {
  account_name = "COMMAND\\your_username"                # your_domain\\your_username
  roles        = ["EnrollPFX", "Administrator", "Nginx"] # List of existing role names to assign to the identity
}