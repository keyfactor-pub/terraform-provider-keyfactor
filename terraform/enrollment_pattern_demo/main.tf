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
#
# Two roles are used in this demo to illustrate the authoritative vs.
# non-authoritative role-management pattern:
#
#   associated_role → bootstrap role, set on pattern create via
#                     associated_role_names; lifecycle.ignore_changes hands
#                     off management after the first apply (GCP iam_binding
#                     analog — whole-array replacement on each apply).
#
#   binding_role    → second role, managed additively via the separate
#                     keyfactor_enrollment_pattern_role_binding resource
#                     (GCP iam_member analog — independent add/remove per
#                     binding resource, never clobbers other roles).
#
# Never mix both patterns on the same enrollment pattern: if you declare
# associated_role_names (without lifecycle.ignore_changes) AND a
# role_binding for the same pattern, every apply of the pattern resource
# will authoritative-replace the role list, potentially removing the roles
# your bindings added.
# ---------------------------------------------------------------------------
data "keyfactor_role" "associated" {
  name = var.associated_role_name
}

data "keyfactor_role" "binding" {
  name = var.binding_role_name
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
# certificate_authority_ids (via restrict_cas) and
# policies.default_certificate_owner_role_id are driven by variables that
# lab-update (see GNUmakefile) changes in place, exercising the
# certificate_authorities/policies.default_certificate_owner_role_name
# mirror follow-the-driver fixes (full-review findings F2/F4) through a
# real Terraform apply -- not just direct Create()/Update() calls, which
# is how these findings originally shipped undetected.
#
# Authoritative role bootstrapping: associated_role_names sets the
# initial role list on create. Because Keyfactor Command requires at least
# one role when use_ad_permissions = false, at least one role must be
# provided here for the create to succeed. After that initial create, the
# lifecycle.ignore_changes block hands off ongoing role membership to the
# keyfactor_enrollment_pattern_role_binding resource below -- subsequent
# applies of this resource will not touch the role list even if
# var.associated_role_name changes.
#
# If you need fully authoritative role management (replacing the entire
# role list on every apply), remove the lifecycle.ignore_changes block
# and do NOT use any role_binding resources for this pattern.
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
  template_default          = false
  use_ad_permissions        = false
  associated_role_names     = [data.keyfactor_role.associated.name]
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

  # Hand off role membership to the role_binding resource after initial
  # create.  Removing this block switches to fully-authoritative mode
  # (every apply replaces the entire role list).
  lifecycle {
    ignore_changes = [associated_role_names]
  }
}

# ---------------------------------------------------------------------------
# Role binding: grant a second role access to this enrollment pattern.
#
# keyfactor_enrollment_pattern_role_binding is the non-authoritative,
# additive resource for role membership (GCP iam_member analog). It adds
# exactly one role to the pattern's membership without touching any other
# roles. This resource manages var.binding_role_name, which is a different
# role from the bootstrap role in associated_role_names above.
#
# Each binding is independently importable by composite key
# "<pattern_name>//<role_name>", and concurrent creates/deletes are safe
# via the provider's GET-modify-PUT-verify retry loop.
#
# Shared-binding caution: if two independent Terraform configs both create
# a role_binding for the same pattern AND the same role, a destroy from
# either config removes the role from the pattern for BOTH -- exactly the
# same limitation as GCP's google_project_iam_member. Each binding config
# should reference a role that only that config "owns."
# ---------------------------------------------------------------------------
resource "keyfactor_enrollment_pattern_role_binding" "demo" {
  enrollment_pattern_name = keyfactor_enrollment_pattern.demo.name
  role_name               = data.keyfactor_role.binding.name
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
