# ---------------------------------------------------------------------------
# OAuth Security Role — read-only certificate permissions
# ---------------------------------------------------------------------------
resource "keyfactor_oauth_security_role" "demo" {
  name              = "OAuthDemo${var.suffix}"
  description       = var.role_description
  permission_set_id = data.keyfactor_permission_set.global.id
  permissions = [
    "/certificates/collections/read/",
    "/certificates/enrollment/",
  ]
}

# ---------------------------------------------------------------------------
# OAuth Security Claim — OAuthClientId bound to a UUID
# ---------------------------------------------------------------------------
resource "keyfactor_oauth_security_claim" "demo" {
  claim_type                     = "OAuthClientId"
  claim_value                    = var.claim_value
  description                    = var.claim_description
  provider_authentication_scheme = var.provider_authentication_scheme
}

# ---------------------------------------------------------------------------
# Association — bind the claim to the role
# ---------------------------------------------------------------------------
resource "keyfactor_oauth_security_role_claim_association" "demo" {
  role_id  = keyfactor_oauth_security_role.demo.id
  claim_id = keyfactor_oauth_security_claim.demo.id
}

# ---------------------------------------------------------------------------
# Data sources — read back the created resources
# ---------------------------------------------------------------------------
data "keyfactor_oauth_security_role" "demo" {
  name = keyfactor_oauth_security_role.demo.name

  depends_on = [keyfactor_oauth_security_role.demo]
}

data "keyfactor_oauth_security_claim" "demo" {
  claim_type                     = keyfactor_oauth_security_claim.demo.claim_type
  claim_value                    = keyfactor_oauth_security_claim.demo.claim_value
  provider_authentication_scheme = keyfactor_oauth_security_claim.demo.provider_authentication_scheme

  depends_on = [keyfactor_oauth_security_claim.demo]
}
