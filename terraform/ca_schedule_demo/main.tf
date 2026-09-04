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
# keyfactor_certificate_authority CA schedule lifecycle validation.
#
# SCHEMA: this release only models the Interval-shaped variant of Command's
# FullScan/IncrementalScan/ThresholdCheck schedules (full_scan_interval_minutes,
# incremental_scan_interval_minutes, threshold_check_interval_minutes). A
# Daily/Weekly/Monthly/ExactlyOnce/Immediate-shaped schedule is not modeled by
# the provider and reads back as null (see scheduleToState in
# resource_keyfactor_certificate_authority.go), which is indistinguishable
# from "no schedule configured" -- an Update() that doesn't touch that
# attribute will therefore omit it from the PUT and Command's full-replace
# semantics clear it. This demo exercises:
#   1. full_scan_interval_minutes declared + changed (in-place update)
#   2. threshold_check_interval_minutes left UNDECLARED (not just null --
#      fully absent from the resource body) so it stays "unmanaged" per the
#      attribute contract, and must survive verbatim across an unrelated
#      update (monitor_thresholds toggle) if it's ever set out-of-band via
#      the API with an Interval shape (step3), while an out-of-band
#      Daily-shaped value (step4) demonstrates the known unmodeled-variant
#      gap above -- the schedule is expected to be wiped by the very next
#      unrelated apply, and a Weekly-shaped value (step5) additionally
#      crashes deserialization (SDK issue #185)
#   3. import round-trip + drift-check
#
# Creates a brand-new, deliberately unreachable CA record (force_save=true
# bypasses Command's connectivity test on create/update) instead of touching
# any of the lab's real CA connections (e.g. id 2, "OpenBao PKI", which has
# a live schedule and associated certificates).
#
# Fix #194 (clearAuthVariant, resource_keyfactor_certificate_authority.go):
# `make destroy` used to reliably fail after step4/step5 ran, with "Error
# clearing CA scan schedules before delete. ... 0xA011000F: Fields for OAuth
# and Client Certificate Authentication cannot both be provided for the same
# CA." Delete()'s "clear scan schedules, then retry delete" fallback shares
# buildCARequest() with Create/Update, which now strips whichever auth
# variant (OAuth vs. client-certificate) isn't actually configured before
# every request, so the stale empty-but-non-null OAuth fields this demo's
# Client Certificate auth used to carry forward from state no longer collide
# with AuthCertificate on the PUT.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_authority" "demo" {
  logical_name = "TFScheduleDemo${var.suffix}"
  host_name    = var.host_name
  ca_type      = 1
  force_save   = true

  standalone                          = false
  new_end_entity_on_renew_and_reissue = true
  configuration_tenant                = "fakeTenant"
  forest_root                         = "fakeTenant"
  monitor_thresholds                  = var.monitor_thresholds

  # This lab's Command instance may reject PUT /CertificateAuthority
  # (Update) for any HTTPS CA lacking an Authentication Certificate, even
  # under forceSave=true, and even though POST (Create) has no such
  # requirement (confirmed on a prior lab; not yet re-confirmed against
  # kfclab). authcert.pfx is a throwaway self-signed cert generated solely
  # to satisfy this if needed, never used for real authentication -- see
  # `make authcert`.
  auth_certificate          = filebase64("${path.module}/authcert.pfx")
  auth_certificate_password = var.auth_certificate_password

  full_scan_interval_minutes        = var.full_scan_interval_minutes
  incremental_scan_interval_minutes = var.incremental_scan_interval_minutes

  # threshold_check_interval_minutes is intentionally NEVER declared here
  # (fully absent, not just null) so it stays permanently
  # "undeclared/unmanaged" -- this is what lets step3/step4 seed an
  # out-of-band value and prove it survives (Interval shape, step3) or fails
  # to survive (Daily shape, step4 -- known unmodeled-variant gap, see
  # header above) an unrelated update (monitor_thresholds toggle) verbatim.
}

output "ca_id" {
  description = "ID of the demo certificate authority."
  value       = keyfactor_certificate_authority.demo.id
}

output "full_scan_interval_minutes" {
  description = "full_scan_interval_minutes as read back into state."
  value       = keyfactor_certificate_authority.demo.full_scan_interval_minutes
}

output "incremental_scan_interval_minutes" {
  description = "incremental_scan_interval_minutes as read back into state."
  value       = keyfactor_certificate_authority.demo.incremental_scan_interval_minutes
}

output "threshold_check_interval_minutes" {
  description = "threshold_check_interval_minutes as read back into state (undeclared in config; should reflect whatever exists server-side, including out-of-band values)."
  value       = keyfactor_certificate_authority.demo.threshold_check_interval_minutes
}
