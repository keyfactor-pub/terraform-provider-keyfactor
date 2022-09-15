provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

# User example
data "keyfactor_identity" "kf_user" {
  account_name = "my-kf-domain\\my-kf-account-name" # The name of the existing identity you want to reference.
}

output "user_metadata" {
  value = {
    id           = keyfactor_identity.kf_user.id
    account_name = keyfactor_identity.kf_user.account_name
    roles        = keyfactor_identity.kf_user.roles
    type         = keyfactor_identity.kf_user.identity_type
    valid        = keyfactor_identity.kf_user.valid
  }
}

# Group example
data "keyfactor_identity" "kf_admins" {
  account_name = "COMMAND\\Keyfactor-Admins"
}

output "group_metadata" {
  value = {
    id           = data.keyfactor_identity.kf_admins.id
    account_name = data.keyfactor_identity.kf_admins.account_name
    roles        = data.keyfactor_identity.kf_admins.roles
    type         = data.keyfactor_identity.kf_admins.identity_type
    valid        = data.keyfactor_identity.kf_admins.valid
  }
}