terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "~> 2.9"
    }
  }
}

provider "keyfactor" {}

# ---------------------------------------------------------------------------
# Data source lookup: discover the certificate template this enrollment
# pattern will be associated with. template_id is immutable on the
# keyfactor_enrollment_pattern resource (RequiresReplace), so this is only
# ever read once per template_name value.
# ---------------------------------------------------------------------------
data "keyfactor_certificate_template" "demo" {
  identifier = var.template_name
}

# ---------------------------------------------------------------------------
# Driver-attribute lookups (full-review Phase 1 required tests, item 3):
# resolve the role/CA names lab-update varies into the IDs the resource
# actually needs.
# ---------------------------------------------------------------------------
data "keyfactor_role" "associated" {
  name = var.associated_role_name
}

data "keyfactor_role" "owner" {
  name = var.owner_role_name
}

data "keyfactor_certificate_authority" "restrict" {
  identifier = var.ca_name
}

# ---------------------------------------------------------------------------
# keyfactor_enrollment_pattern resource under test.
#
# associated_role_names/certificate_authority_ids are write-only: Keyfactor
# Command expands them into associated_roles/certificate_authorities on read
# and never echoes back the plain name/ID list, so the provider preserves
# the last-known value from state on refresh (see
# resource_keyfactor_enrollment_pattern.go). That means `lab-drift-check`
# below is expected to show no diff on these fields even though the API
# never actually confirms them back.
#
# associated_role_names, certificate_authority_ids (via restrict_cas), and
# policies.default_certificate_owner_role_id are driven by variables that
# lab-update (see GNUmakefile) changes in place, exercising the
# associated_roles/certificate_authorities/policies.default_certificate_
# owner_role_name mirror follow-the-driver fixes (full-review findings
# F2/F4) through a real Terraform apply -- not just direct Create()/Update()
# calls, which is how these findings originally shipped undetected.
#
# force_template_default is deliberately NOT exercised here -- see
# variables.tf's comment for why (it would steal TemplateDefault status
# from kfclab's shared seed pattern for this template and break this
# demo's own destroy step). It is covered by a dedicated Go test instead.
# ---------------------------------------------------------------------------
resource "keyfactor_enrollment_pattern" "demo" {
  name                      = "Demo Pattern${var.suffix}"
  template_id               = data.keyfactor_certificate_template.demo.id
  description               = var.description_override != "" ? var.description_override : "Terraform harness demo pattern"
  allowed_enrollment_types  = 3 # 1=CSR, 2=PFX, 3=both
  associated_role_names     = [var.associated_role_name]
  template_default          = false
  restrict_cas              = true
  certificate_authority_ids = [tonumber(data.keyfactor_certificate_authority.restrict.id)]

  policies = {
    certificate_owner_role             = 2 # Specified
    default_certificate_owner_override = true
    default_certificate_owner_role_id  = data.keyfactor_role.owner.id
  }

  # Every other policies.* sub-field (allow_key_reuse, allow_wildcards,
  # rfc_enforcement, primary_key_algorithms, alternative_key_algorithms) is
  # intentionally left undeclared: Keyfactor Command requires a Policies
  # object on every create/update, but the provider always sends one
  # internally (see buildEnrollmentPatternPolicyRequest in
  # resource_keyfactor_enrollment_pattern.go) regardless of whether this
  # attribute is set, so server-side defaults apply automatically for the
  # sub-fields not declared above.
}

# ---------------------------------------------------------------------------
# Data source gap fill: read the pattern back by name and assert it agrees
# with the resource's own state.
# ---------------------------------------------------------------------------
data "keyfactor_enrollment_pattern" "demo" {
  identifier = keyfactor_enrollment_pattern.demo.name

  depends_on = [keyfactor_enrollment_pattern.demo]
}

output "pattern_id" {
  description = "Integer ID of the demo enrollment pattern."
  value       = keyfactor_enrollment_pattern.demo.id
}

output "datasource_readback_matches" {
  description = "True if data.keyfactor_enrollment_pattern's view agrees with the resource."
  value       = data.keyfactor_enrollment_pattern.demo.id == keyfactor_enrollment_pattern.demo.id
}
