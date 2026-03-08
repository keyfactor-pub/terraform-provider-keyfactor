# Third-party CA (EJBCA) with OAuth authentication
resource "keyfactor_certificate_authority" "ejbca" {
  logical_name         = "My-EJBCA-CA"
  host_name            = "http://ejbca.example.com:8082/ejbca"
  ca_type              = 1
  forest_root          = "ejbca"
  configuration_tenant = "ejbca"

  allowed_enrollment_types = 3
  key_retention            = 1

  use_allowed_requesters = true
  allowed_requesters     = ["InstanceOwner"]

  allow_one_click_renewals            = true
  new_end_entity_on_renew_and_reissue = true

  full_scan_interval_minutes        = 60
  incremental_scan_interval_minutes = 10

  token_url     = "https://auth.example.com/oauth2/token"
  client_id     = "my-client-id"
  client_secret = var.ejbca_client_secret
}

# Import an existing CA
# terraform import keyfactor_certificate_authority.ejbca 1
