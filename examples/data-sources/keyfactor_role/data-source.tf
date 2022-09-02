provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_role" "kf_role" {
  role_name = "Administrator" # The name of the existing role you want to reference
}