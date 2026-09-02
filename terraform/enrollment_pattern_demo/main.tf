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
# keyfactor_enrollment_pattern resource under test.
#
# associated_role_names is write-only: Keyfactor Command expands it into
# associated_roles on read and never echoes back the plain name list, so the
# provider preserves the last-known value from state on refresh (see
# resource_keyfactor_enrollment_pattern.go). That means `lab-drift-check`
# below is expected to show no diff on this field even though the API never
# actually confirms it back.
# ---------------------------------------------------------------------------
resource "keyfactor_enrollment_pattern" "demo" {
  name                     = "Demo Pattern${var.suffix}"
  template_id              = data.keyfactor_certificate_template.demo.id
  description              = var.description_override != "" ? var.description_override : "Terraform harness demo pattern"
  allowed_enrollment_types = 3 # 1=CSR, 2=PFX, 3=both
  associated_role_names    = ["InstanceAdmin"]
  template_default         = false
  restrict_cas             = false

  # policies is intentionally left undeclared: Keyfactor Command requires a
  # Policies object on every create/update, but the provider always sends
  # one internally (see buildEnrollmentPatternPolicyRequest in
  # resource_keyfactor_enrollment_pattern.go) regardless of whether this
  # attribute is set, so server-side defaults apply automatically. Declaring
  # `policies = {}` here used to be required to avoid a "Value Conversion
  # Error: unhandled unknown value" crash (primary_key_algorithms/
  # alternative_key_algorithms are Go slices, which cannot hold an Unknown
  # value at Plan.Get() time) -- that crash is now avoided by simply never
  # declaring policies at all, so its Computed subfields are never put in
  # the "known parent object, unknown children" state that triggered it.
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
