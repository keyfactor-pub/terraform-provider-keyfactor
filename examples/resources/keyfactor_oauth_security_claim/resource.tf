resource "keyfactor_oauth_security_claim" "subject_system_claim" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "example_username" # Format will vary by identity provider
  description                    = "Example oAuth Subject Claim"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_claim" "object_id_system_claim" {
  claim_type                     = "OAuthOid"
  claim_value                    = "9689d5e3-d565-4dda-bf93-a48ec614b311" # Format will vary by identity provider
  description                    = "Example oAuth Object ID Claim"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_claim" "group_system_claim" {
  claim_type                     = "OAuthRole"
  claim_value                    = "Example Role Name" # Format will vary by identity provider
  description                    = "Example oAuth role claim"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_claim" "client_id_system_claim" {
  claim_type                     = "OAuthClientId"
  claim_value                    = "9689d5e3-d565-4dda-bf93-a48ec614b311" # Format will vary by identity provider
  description                    = "Example oAuth Client ID claim"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_claim" "ad_user_claim" {
  claim_type                     = "User"
  claim_value                    = "EXAMPLE\\terraformer"
  description                    = "Example Security Claim for Active Directory User"
  provider_authentication_scheme = "Active Directory"
}

resource "keyfactor_oauth_security_claim" "ad_group_claim" {
  claim_type                     = "Group"
  claim_value                    = "EXAMPLE\\Terraformers"
  description                    = "Example Security Claim for Active Directory Group"
  provider_authentication_scheme = "Active Directory"
}

# OAuthRole and OAuthSubject claims bound to a third-party OIDC provider
# (e.g. Entra ID). claim_type takes the string form, not the numeric
# CSSCMSCoreEnumsClaimType value Command's API uses internally (4 and 5
# respectively) -- see the claim_type attribute description above.
resource "keyfactor_oauth_security_claim" "team_role_claim" {
  description                    = "Entra group - team access"
  claim_type                     = "OAuthRole" # was numeric 4
  claim_value                    = "Keyfactor : Internal : Access : <app>"
  provider_authentication_scheme = "entra_ent_prod"
}

resource "keyfactor_oauth_security_claim" "api_role_claim" {
  description                    = "Entra service principal - API access"
  claim_type                     = "OAuthSubject" # was numeric 5
  claim_value                    = "<service-principal-object-id>"
  provider_authentication_scheme = "entra_ent_prod"
}
