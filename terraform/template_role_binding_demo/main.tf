terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.0"
    }
  }
}

provider "keyfactor" {}

# ---------------------------------------------------------------------------
# keyfactor_template_role_binding full-lifecycle smoke test.
#
# Proves PR #179's fix to resource_keyfactor_template_role_binding.go: Read()
# silently swallowed a GetTemplates() API error (no diagnostic, no early
# return), unlike Create()'s identical call which already handled it
# correctly. Read() now mirrors Create()'s AddError + return handling.
#
# This demo attaches a purpose-built role to var.template_short_name (an
# EXISTING template already using UseAllowedRequesters -- see the lab
# discovery below) and verifies via `terraform plan` after apply/import that
# only the added role shows up, and the template's pre-existing
# AllowedRequesters entries are left alone. That "don't touch unrelated
# requesters" behavior is a different, already-covered fix in this same
# file; this demo's real purpose is exercising the ordinary Read() happy
# path end-to-end via the real terraform CLI, as a regression guard for the
# swallowed-error fix (a full lifecycle can't easily force GetTemplates() to
# fail, but it proves the ordinary non-error Read() path -- exercised on
# every plan/refresh in this demo -- still works correctly after the fix).
#
# KNOWN BLOCKER (discovered validating this demo against
# int25-4-1.kftestlab.com, unrelated to PR #179): `apply` currently fails on
# EVERY template in this lab (checked all 5 via `make api-list-templates`)
# with "Error updating template in Keyfactor: 'Policies' cannot be empty".
# keyfactor-go-client/v3's UpdateTemplateArg (template_models.go) has no
# `Policies` field at all, and buildTemplateRoleBindingUpdateArg in
# resource_keyfactor_template_role_binding.go never sets one -- this looks
# like a genuine, separate SDK/Command-API-version gap (Command now requires
# a field the SDK's request model doesn't model), not something introduced
# or touched by PR #179. Attach/detach against this lab is blocked until
# that's fixed; this demo's `apply` step will fail until then. Filed as a
# follow-up, not fixed here -- out of scope for PR #179's Read()-only fix.
# ---------------------------------------------------------------------------
resource "keyfactor_role" "demo" {
  name        = "TemplateRoleBindingDemo${var.suffix}"
  description = "Terraform-managed role (PR179 template_role_binding demo)"
  permissions = []
}

resource "keyfactor_template_role_binding" "demo" {
  role_name             = keyfactor_role.demo.name
  template_short_names  = [var.template_short_name]

  depends_on = [keyfactor_role.demo]
}

output "role_name" {
  description = "Name of the created security role."
  value       = keyfactor_role.demo.name
}

output "binding_id" {
  description = "ID of the template role binding."
  value       = keyfactor_template_role_binding.demo.id
}

output "template_short_names" {
  description = "Template short names currently bound to the role in Terraform state."
  value       = keyfactor_template_role_binding.demo.template_short_names
}
