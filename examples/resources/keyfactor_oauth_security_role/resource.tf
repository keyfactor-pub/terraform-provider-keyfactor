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
  name        = "Certificate Admin"
  description = "A security role created through Terraform"
  # permission_set_id = "099c05f0-deba-4562-a5b1-f491e19c0749" # Global
  permission_set_id = data.keyfactor_permission_set.global_permission_set.id
  permissions = [
    "/certificates/",
    "/metadata/types/read/",
  ]
  # email_address = "foo.bar@example.com"
  claims = [
    {
      description                    = resource.keyfactor_oauth_security_claim.system_claim.description
      claim_type                     = resource.keyfactor_oauth_security_claim.system_claim.claim_type
      claim_value                    = resource.keyfactor_oauth_security_claim.system_claim.claim_value
      provider_authentication_scheme = resource.keyfactor_oauth_security_claim.system_claim.provider_authentication_scheme
    }
  ]
}
