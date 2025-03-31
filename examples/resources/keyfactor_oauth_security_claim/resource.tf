provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

resource "keyfactor_oauth_security_claim" "system_claim_123" {
  claim_type                     = "OAuthSubject"
  claim_value                    = "1234567890"
  description                    = "Security Claim for System"
  provider_authentication_scheme = "System"
}
