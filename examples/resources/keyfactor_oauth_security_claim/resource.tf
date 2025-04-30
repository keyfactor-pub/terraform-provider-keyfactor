resource "keyfactor_oauth_security_claim" "subject_system_claim" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "example_username" # Format will vary by identity provider
  description                    = "Example oAuth Subject Claim"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_claim" "group_system_claim" {
  claim_type                     = "OAuthRole"
  claim_value                    = "Example Role Name" # Format will vary by identity provider
  description                    = "Example oAuth role claim"
  provider_authentication_scheme = "System"
}

resource "keyfactor_oauth_security_claim" "group_system_claim" {
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