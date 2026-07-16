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
# keyfactor_certificate_authority import/read smoke test.
#
# This resource wasn't behaviorally changed by PR #179 -- only 3 of its
# nil-pointer-to-Int64 enum converters (enrollmentTypePtrToTfInt64,
# keyRetentionPtrToTfInt64, cleanupTimeUnitsPtrToTfInt64) were refactored to
# delegate to the new shared generic helper enumPtrToTfInt64[T ~int32] in
# helpers.go, replacing 3x5 lines of hand-duplicated logic with 3 one-line
# calls. No behavior change was intended.
#
# Unlike the other PR #179 demos, this one deliberately does NOT create a
# new CA registration from scratch: `keyfactor_certificate_authority` create
# targets a real, already-configured CA connection (host/token/client
# credentials), and there is exactly one real CA in this lab
# (int25-4-1.kftestlab.com's "Sub-CA", CAType=1/EJBCA, discovered via
# `make api-get-ca CA_ID=1`) -- fabricating a second one risks colliding with
# or confusing the lab's actual PKI setup for no real benefit, since the
# refactor only touches how Read() converts already-fetched enum values.
#
# Instead this demo IMPORTS the lab's existing CA and confirms the import +
# subsequent Read/refresh round-trips its enrollment_type/key_retention/
# cleanup_time_units fields correctly -- exactly the fields the refactored
# converters handle -- without ever creating, updating, or destroying the
# real CA connection.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_authority" "sub_ca" {
  logical_name = var.logical_name
  host_name    = var.host_name
  ca_type      = var.ca_type

  lifecycle {
    # This demo only imports and reads; never plan a destroy/replace against
    # the lab's one real CA connection.
    prevent_destroy = true
  }
}

output "ca_id" {
  description = "ID of the certificate authority."
  value       = keyfactor_certificate_authority.sub_ca.id
}

output "allowed_enrollment_types" {
  description = "allowed_enrollment_types as read back into Terraform state (exercises enrollmentTypePtrToTfInt64)."
  value       = keyfactor_certificate_authority.sub_ca.allowed_enrollment_types
}

output "key_retention" {
  description = "key_retention as read back into Terraform state (exercises keyRetentionPtrToTfInt64)."
  value       = keyfactor_certificate_authority.sub_ca.key_retention
}

output "time_after_expiration_units" {
  description = "time_after_expiration_units as read back into Terraform state (exercises cleanupTimeUnitsPtrToTfInt64; expected null on this CA, which has certificate cleanup disabled)."
  value       = keyfactor_certificate_authority.sub_ca.time_after_expiration_units
}
