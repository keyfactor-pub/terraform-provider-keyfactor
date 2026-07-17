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
# This demo exists to prove PR #178: resourceSecurityRole.Read previously
# never called the Keyfactor Command API -- it just re-echoed whatever was
# already in Terraform state, so out-of-band changes made directly against
# Command (not through Terraform) were invisible to `terraform plan`. The
# fix makes Read call GetSecurityRole and rebuild state from the live
# server response.
#
# `make lab-oob-drift` (see GNUmakefile) applies this resource, then mutates
# its permissions directly via a raw Command REST API call (bypassing
# Terraform entirely), then asserts `terraform plan` reports drift instead
# of "No changes" -- which is exactly the false negative this PR fixes.
# ---------------------------------------------------------------------------
resource "keyfactor_role" "demo" {
  name        = "SecurityRoleDemo${var.suffix}"
  description = var.role_description
  permissions = [
    "Certificates:Read",
  ]
}

output "role_id" {
  description = "ID of the created security role."
  value       = keyfactor_role.demo.id
}

output "role_name" {
  description = "Name of the created security role."
  value       = keyfactor_role.demo.name
}
