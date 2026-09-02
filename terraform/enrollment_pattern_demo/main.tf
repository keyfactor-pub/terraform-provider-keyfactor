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

  # Keyfactor Command requires a Policies object on every create/update;
  # an empty object is enough to inherit system-wide policy defaults. This
  # is a SingleNestedAttributes (object-typed argument), not an HCL block --
  # `policies {}` fails validation with "Unsupported block type".
  policies = {}
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
