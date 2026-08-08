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
# ADDITIONAL PROVIDER BUG confirmed against kfclab (Command 25.5, 2026-08-07):
# `make lab-update` here instead fails with a DIFFERENT 400 --
# "0xA011000F: Enrollment Pattern needs to have at least one associated
# role." Root cause: this resource's Update() (buildTemplateUpdateRequest in
# resource_keyfactor_certificate_template.go) only sets AllowedRequesters on
# the PUT request if `allowed_requesters` is explicitly declared in config;
# since this demo (like most real-world usage) only sets `friendly_name`,
# AllowedRequesters is omitted -- and unlike keyfactor_certificate_authority's
# schedule fields, this attribute has no UseStateForUnknown plan modifier, so
# it plans as null rather than carrying forward the prior state value. The
# resulting PUT clears AllowedRequesters server-side, which then fails
# Command's validation for any template whose enrollment pattern requires an
# associated role (as this lab's "Lab - AnyCA (lab-role)" pattern does).
# Confirmed via a raw API PUT that preserves AllowedRequesters verbatim: the
# SAME friendly_name-only change succeeds when AllowedRequesters isn't
# dropped, isolating the bug to the omission rather than to friendly_name
# itself. This is a second, independent provider bug from the "'Policies'
# cannot be empty" one above -- both currently make `make lab-update` FAIL
# on this lab.
#
# This demo exists specifically to SURFACE these failures clearly (a FAIL on
# `make lab-update`, not a crash) rather than to guarantee updates work here.
# If the lab's Command instance does NOT have either gap, `make lab-update`
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
