data "keyfactor_permission_set" "global_permission_set" {
  name = "Global"
}

resource "keyfactor_oauth_security_claim" "subject_system_claim_1" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "example_username_1" # Format will vary by identity provider
  description                    = "Example 1 oAuth Subject claim"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_claim" "subject_system_claim_2" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "example_username_2" # Format will vary by identity provider
  description                    = "Example 2 oAuth Subject claim"
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

resource "keyfactor_oauth_security_role_claim_association" "subject_system_claim_bind_certificate_admin_role_1" {
  role_id  = keyfactor_oauth_security_role.certificate_admin_role.id
  claim_id = keyfactor_oauth_security_claim.subject_system_claim_1.id
}

resource "keyfactor_oauth_security_role_claim_association" "subject_system_claim_bind_certificate_admin_role_2" {
  role_id    = keyfactor_oauth_security_role.certificate_admin_role.id
  claim_id   = keyfactor_oauth_security_claim.subject_system_claim_2.id
  depends_on = [keyfactor_oauth_security_role_claim_association.subject_system_claim_bind_certificate_admin_role_1] # Optional
}
