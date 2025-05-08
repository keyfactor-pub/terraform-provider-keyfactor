# NOTE: This resource type is deprecated as of Keyfactor Command v11 please use `keyfactor_oauth_security_claim resources`.
resource "keyfactor_identity" "identity" {
  account_name = "COMMAND\\your_username"                # your_domain\\your_username
  roles        = ["EnrollPFX", "Administrator", "Nginx"] # List of existing role names to assign to the identity
}