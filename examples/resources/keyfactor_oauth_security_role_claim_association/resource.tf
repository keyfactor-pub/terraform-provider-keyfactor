provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

data "keyfactor_permission_set" "global_permission_set" {
  name = "Global"
}

resource "keyfactor_oauth_security_claim" "system_claim" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "1234567890"
  description                    = "Security Claim for System"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_role" "certificate_admin_role" {
  name              = "Certificate Admin"
  description       = "A security role created through Terraform"
  permission_set_id = data.keyfactor_permission_set.global_permission_set.id
  permissions = [
    "/certificates/",
    "/metadata/types/read/",
  ]
}

resource "keyfactor_oauth_security_role_claim_association" "cert_admin_system_claim_role" {
  role_id  = resource.keyfactor_oauth_security_role.certificate_admin_role.id
  claim_id = resource.keyfactor_oauth_security_claim.system_claim.id
}
