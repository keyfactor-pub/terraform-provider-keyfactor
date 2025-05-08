provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_oauth_security_claim" "existing_claim" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "1234567890"
  provider_authentication_scheme = "System"
}

output "existing_claim" {
  value = {
    id                             = data.keyfactor_oauth_security_claim.existing_claim.id
    claim_type                     = data.keyfactor_oauth_security_claim.existing_claim.claim_type
    claim_value                    = data.keyfactor_oauth_security_claim.existing_claim.claim_value
    description                    = data.keyfactor_oauth_security_claim.existing_claim.description
    provider_authentication_scheme = data.keyfactor_oauth_security_claim.existing_claim.provider_authentication_scheme
    provider                       = data.keyfactor_oauth_security_claim.existing_claim.provider
  }
}
