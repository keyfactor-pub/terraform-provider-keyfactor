data "keyfactor_permission_set" "global_permission_set" {
  name = "Global"
}

resource "keyfactor_oauth_security_claim" "subject_system_claim" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "example_username" # Format will vary by identity provider
  description                    = "Example oAuth subject claim"
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

resource "keyfactor_oauth_security_role_claim_association" "subject_system_claim_bind_certificate_admin_role" {
  role_id  = keyfactor_oauth_security_role.certificate_admin_role.id
  claim_id = keyfactor_oauth_security_claim.subject_system_claim.id
}
