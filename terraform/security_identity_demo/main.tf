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
# Legacy Active Directory security identity (keyfactor_identity).
#
# This demo proves PR #179's fix to resource_keyfactor_security_identity.go:
#
#   resourceSecurityIdentity.Update() deliberately writes a concrete,
#   non-null `roles` list into the result whenever config omits `roles`, to
#   preserve the identity's existing role assignments across an unrelated
#   Update. But `roles` was Optional and NOT Computed, so Terraform Core
#   planned an omitted `roles` attribute as Null directly from config -- with
#   no path for a provider-side plan modifier to intervene. Any identity
#   with roles already assigned then crashed `terraform apply` with:
#
#     Provider produced inconsistent result after apply: .roles: was null,
#     but now cty.ListVal(...)
#
# The fix marks `roles` Optional+Computed with a UseStateForUnknown plan
# modifier, so an omitted `roles` attribute now resolves to "carry forward
# the prior state value" instead of planning Null -- which, unlike the
# sibling keyfactor_role/permissions fix, is ENOUGH on its own to trigger
# the crash: the plan diff on `roles` alone (list -> null) is what causes
# Terraform Core to call Update in the first place, no unrelated attribute
# needs to change (keyfactor_identity has no other user-settable attribute
# besides account_name, which is RequiresReplace).
#
# `make lab-omit-roles-update` (see GNUmakefile) applies this identity WITH
# roles declared, then applies again with roles omitted from config
# (roles_declared = false, which plans identically to a fully-absent
# attribute at the protocol level) -- this must succeed without the
# inconsistent-result crash, and the identity's role assignment must remain
# present server-side afterward.
#
# IMPORTANT LAB CONSTRAINT: keyfactor_identity manages legacy Active
# Directory identities only (see the resource's DeprecationMessage). The
# default lab (kfclab, Authentik OAuth-backed, no AD) rejects ANY account
# name here with HTTP 400 "Could not validate identity ... This operation
# only supports Active Directory identities" -- confirmed directly against
# POST /Security/Identities. This is a hard, structural lab constraint (no
# AD backing exists to validate against), not a provider defect: this
# resource cannot be created against an OAuth-only lab regardless of
# provider code correctness. The GNUmakefile's `lifecycle` target defaults
# to SKIP_LAB_AD=1 and prints "SKIPPED: ..." instead of failing the harness;
# set SKIP_LAB_AD=0 and point account_name at a real AD-backed lab account
# not yet registered as a Keyfactor security identity to exercise this demo
# end-to-end.
# ---------------------------------------------------------------------------
resource "keyfactor_identity" "demo" {
  account_name = var.account_name
  # An explicit HCL `null` and a fully-omitted attribute both decode to a
  # null config value at the protocol level, so this ternary exercises the
  # exact "omitted from config" code path without needing two separate .tf
  # files for the two apply steps.
  roles = var.roles_declared ? var.roles : null
}

# ---------------------------------------------------------------------------
# Data source gap fill: read the identity back and assert it agrees with the
# resource's own state.
# ---------------------------------------------------------------------------
data "keyfactor_identity" "demo" {
  account_name = keyfactor_identity.demo.account_name

  depends_on = [keyfactor_identity.demo]
}

output "identity_id" {
  description = "ID of the created security identity."
  value       = keyfactor_identity.demo.id
}

output "identity_readback_matches" {
  description = "True if data.keyfactor_identity's view of the identity agrees with the resource's own state."
  value       = data.keyfactor_identity.demo.id == keyfactor_identity.demo.id
}

output "identity_account_name" {
  description = "Account name of the created security identity."
  value       = keyfactor_identity.demo.account_name
}

output "identity_roles" {
  description = "Roles currently in Terraform state for the identity."
  value       = keyfactor_identity.demo.roles
}
