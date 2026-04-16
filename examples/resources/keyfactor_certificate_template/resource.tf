# Templates cannot be created via API — import an existing template by integer ID:
# terraform import keyfactor_certificate_template.webserver 5

resource "keyfactor_certificate_template" "webserver" {
  # Restrict to PFX enrollment only and require approval
  allowed_enrollment_types = 1
  requires_approval        = true

  use_allowed_requesters = true
  allowed_requesters     = ["CertAdmins", "WebOps"]

  template_policy {
    allow_wildcards = false
    rfc_enforcement = true

    key_info {
      rsa {
        bit_lengths = [2048, 4096]
      }
    }
  }

  template_regexes {
    subject_part   = "CN"
    regex          = "^[a-z0-9-]+\\.example\\.com$"
    error          = "CN must be a subdomain of example.com"
    case_sensitive = false
  }

  template_defaults {
    subject_part = "O"
    value        = "Example Corp"
  }
}

# Example showing certificate cleanup settings (Command v25+)
resource "keyfactor_certificate_template" "webserver_with_cleanup" {
  allowed_enrollment_types = 3 # PFX + CSR

  # Automatically clean up expired certificates after 30 days
  certificate_cleanup_enabled = true
  time_after_expiration       = 30
  time_after_expiration_units = 0 # 0=Days, 1=Weeks, 2=Months
  delete_with_archived_key    = false
}
