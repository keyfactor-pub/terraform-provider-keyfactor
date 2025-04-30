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
    # This is a set of all currently available permission values, as of writing, for easy reference.
    # This set contains overlapping permissions, so this set will not work as-is.
    # Refine this permission set to the values necessary for the security role.
    "/",
    "/agents/",
    "/agents/auto_registration/",
    "/agents/auto_registration/modify/",
    "/agents/auto_registration/read/",
    "/agents/management/",
    "/agents/management/mac/",
    "/agents/management/mac/auto-enrollment/",
    "/agents/management/mac/auto-enrollment/management/",
    "/agents/management/mac/auto-enrollment/management/modify/",
    "/agents/management/mac/auto-enrollment/management/read/",
    "/agents/management/modify/",
    "/agents/management/read/",
    "/application_settings/",
    "/application_settings/modify/",
    "/application_settings/read/",
    "/auditing/",
    "/auditing/read/",
    "/certificate_authorities/",
    "/certificate_authorities/modify/",
    "/certificate_authorities/read/",
    "/certificate_stores/",
    "/certificate_stores/modify/",
    "/certificate_stores/read/",
    "/certificate_stores/schedule/",
    "/certificate_templates/",
    "/certificate_templates/modify/",
    "/certificate_templates/read/",
    "/certificates/",
    "/certificates/collections/",
    "/certificates/collections/change_owner/",
    "/certificates/collections/delete/",
    "/certificates/collections/metadata/modify/",
    "/certificates/collections/modify/",
    "/certificates/collections/private_key/import/",
    "/certificates/collections/private_key/read/",
    "/certificates/collections/read/",
    "/certificates/collections/revoke/",
    "/certificates/enrollment/",
    "/certificates/enrollment/csr_generation/",
    "/certificates/enrollment/csr/",
    "/certificates/enrollment/pfx/",
    "/certificates/import/",
    "/certificates/requests/manage/",
    "/dashboard/",
    "/dashboard/read/",
    "/dashboard/risk_header/",
    "/dashboard/risk_header/read/",
    "/identity_providers/",
    "/identity_providers/modify/",
    "/identity_providers/read/",
    "/metadata/",
    "/metadata/types/",
    "/metadata/types/modify/",
    "/metadata/types/read/",
    "/monitoring/",
    "/monitoring/alerts/",
    "/monitoring/alerts/modify/",
    "/monitoring/alerts/read/",
    "/monitoring/alerts/schedule/",
    "/monitoring/alerts/schedule/revocation/",
    "/monitoring/alerts/test/",
    "/monitoring/handlers/",
    "/monitoring/handlers/registration/",
    "/monitoring/handlers/registration/modify/",
    "/monitoring/handlers/registration/read/",
    "/pam/",
    "/pam/modify/",
    "/pam/read/",
    "/portal/",
    "/portal/read/",
    "/reports/",
    "/reports/modify/",
    "/reports/read/",
    "/scripts/",
    "/scripts/modify/",
    "/scripts/read/",
    "/security/",
    "/security/modify/",
    "/security/read/",
    "/ssh/",
    "/ssh/enterprise_admin/",
    "/ssh/server_admin/",
    "/ssh/user/",
    "/ssl/",
    "/ssl/modify/",
    "/ssl/read/",
    "/system_settings/",
    "/system_settings/modify/",
    "/system_settings/read/",
    "/workflows/",
    "/workflows/definitions/",
    "/workflows/definitions/modify/",
    "/workflows/definitions/read/",
    "/workflows/instances/",
    "/workflows/instances/manage/",
    "/workflows/instances/read/",
    "/workflows/instances/read/mine/",
    "/workflows/instances/read/pending/"
  ]
  # email_address = "foo.bar@example.com"
}
