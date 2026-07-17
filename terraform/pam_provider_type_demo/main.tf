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
# keyfactor_pam_provider_type full-lifecycle smoke test.
#
# This resource wasn't behaviorally changed by PR #179 -- only its
# nil-pointer-to-Int64 DataType converter (pamParameterDataTypePtrToTfInt64)
# was refactored to delegate to a new shared generic helper
# (enumPtrToTfInt64[T ~int32] in helpers.go), replacing 5 lines of
# hand-duplicated logic with a one-line call. No behavior change was
# intended. This demo exists to prove that refactor didn't regress the real
# create/read/import round-trip for the `parameters[].data_type` field,
# which is exactly the field enumPtrToTfInt64 converts.
# ---------------------------------------------------------------------------
resource "keyfactor_pam_provider_type" "demo" {
  name = "PamProviderTypeDemo${var.suffix}"

  parameters = [
    {
      name           = "Hostname"
      display_name   = "PAM Server Hostname"
      data_type      = 1 # string
      instance_level = false
    },
    {
      name           = "Password"
      display_name   = "PAM Account Password"
      data_type      = 2 # secret
      instance_level = false
    },
  ]
}

output "pam_provider_type_id" {
  description = "ID of the created PAM provider type."
  value       = keyfactor_pam_provider_type.demo.id
}

output "pam_provider_type_name" {
  description = "Name of the created PAM provider type."
  value       = keyfactor_pam_provider_type.demo.name
}

output "pam_provider_type_parameters" {
  description = "Parameters currently in Terraform state for the PAM provider type."
  value       = keyfactor_pam_provider_type.demo.parameters
}
