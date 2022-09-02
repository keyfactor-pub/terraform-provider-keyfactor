provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_identity" "kf_user" {
  account_name = "my-kf-domain\\my-kf-account-name" # The name of the existing identity you want to reference.
}