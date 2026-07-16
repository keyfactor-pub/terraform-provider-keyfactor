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
# Legacy (Active Directory / Version 1 permission model) security role.
#
# This demo is a SEPARATE, purpose-built proof from terraform/security_role_demo/
# (left untouched -- that demo already proves PR #178's out-of-band drift-detection
# fix via its `lab-oob-drift` target). This demo proves the DIFFERENT PR #179 fix:
#
#   resourceSecurityRole.Update() deliberately writes a concrete, non-null
#   `permissions` list into the result whenever config omits `permissions`, to
#   preserve the role's existing permissions across an unrelated Update (e.g.
#   changing only `description`). But `permissions` was Optional and NOT
#   Computed, so Terraform Core planned an omitted `permissions` attribute as
#   Null directly from config -- with no path for a provider-side plan
#   modifier to intervene. Any role with permissions already assigned then
#   crashed `terraform apply` on any unrelated Update with:
#
#     Provider produced inconsistent result after apply: .permissions: was
#     null, but now cty.ListVal(...)
#
# The fix marks `permissions` Optional+Computed with a UseStateForUnknown
# plan modifier, so Terraform Core now resolves an omitted `permissions`
# attribute to "carry forward the prior state value" instead of planning
# Null, and the Update logic keys off request.Config (never touched by plan
# modifiers) rather than request.Plan to correctly distinguish "omitted"
# from "explicitly re-declared."
#
# `make lab-omit-permissions-update` (see GNUmakefile) is the regression
# proof: it applies this role WITH permissions declared, then applies again
# with `description` changed (the unrelated attribute) AND `permissions`
# omitted from config entirely (permissions_declared = false, which plans
# identically to omitting the attribute -- an explicit HCL `null` and a
# fully-absent attribute both decode to a null config value at the
# protocol level). This must succeed without the inconsistent-result crash,
# and the role's permissions must remain intact server-side afterward.
# ---------------------------------------------------------------------------
resource "keyfactor_role" "demo" {
  name        = "SecurityRolePermsDemo${var.suffix}"
  description = var.role_description
  # An explicit HCL `null` and a fully-omitted attribute both decode to a
  # null config value at the protocol level, so this ternary exercises the
  # exact "omitted from config" code path without needing two separate .tf
  # files for the two apply steps.
  permissions = var.permissions_declared ? var.permissions : null
}

output "role_id" {
  description = "ID of the created security role."
  value       = keyfactor_role.demo.id
}

output "role_name" {
  description = "Name of the created security role."
  value       = keyfactor_role.demo.name
}

output "role_permissions" {
  description = "Permissions currently in Terraform state for the role."
  value       = keyfactor_role.demo.permissions
}
