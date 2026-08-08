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
# keyfactor_certificate_template import + update demo.
#
# Templates cannot be CREATED via the Command API -- this resource must be
# imported by integer ID (`make lab-import-existing`, or `terraform import
# keyfactor_certificate_template.demo <id>`) against an existing template.
# This demo targets the kfclab lab's "AnyCA_lab-role" template (id 6, per
# lab inventory) by default.
#
# KNOWN LAB CONSTRAINT: some Command instances reject ANY template update
# with "Error updating template in Keyfactor: 'Policies' cannot be empty" --
# keyfactor-go-client/v3's UpdateTemplateArg has no `Policies` field at all,
# so this looks like a genuine SDK/Command-API-version gap (Command now
# requires a field the SDK's request model doesn't send), not a config
# mistake in this demo. See terraform/template_role_binding_demo/main.tf for
# the same constraint noted independently.
#
# This demo exists specifically to SURFACE that failure clearly (a FAIL on
# `make lab-update`, not a crash) rather than to guarantee updates work here.
# If the lab's Command instance does NOT have this gap, `make lab-update`
# passes normally.
# ---------------------------------------------------------------------------
data "keyfactor_certificate_template" "demo" {
  identifier = var.template_short_name
}

resource "keyfactor_certificate_template" "demo" {
  # Populated by `terraform import` -- see GNUmakefile's lab-import-existing.
  # friendly_name is the one field this demo mutates to exercise Update();
  # see variables.tf's friendly_name_override.
  friendly_name = var.friendly_name_override != "" ? var.friendly_name_override : data.keyfactor_certificate_template.demo.display_name
}

output "template_id" {
  description = "Integer ID of the imported certificate template."
  value       = data.keyfactor_certificate_template.demo.id
}

output "template_display_name" {
  description = "Current display name of the template, as read via the data source."
  value       = data.keyfactor_certificate_template.demo.display_name
}

output "resource_friendly_name" {
  description = "friendly_name currently in Terraform state for the managed resource."
  value       = keyfactor_certificate_template.demo.friendly_name
}
