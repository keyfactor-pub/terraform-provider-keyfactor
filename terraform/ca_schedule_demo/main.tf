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
# SCHEMA NOTE (confirmed against the released v2.9.1 provider, 2026-08-07):
# this demo was originally written against a Daily/Weekly/Monthly CA scan
# schedule variant model (full_scan_daily_time, sentinel-clear semantics,
# per-variant ThresholdCheck) referenced by PRs #173/#182/#184 in its
# original header comments. That variant model does NOT exist in the
# released schema or in this repo's current HEAD -- `keyfactor_certificate_authority`
# only exposes FLAT interval-minutes schedule fields:
# full_scan_interval_minutes, incremental_scan_interval_minutes,
# threshold_check_interval_minutes (all Optional+Computed int64,
# UseStateForUnknown). There is no Daily/Weekly/Monthly/ExactlyOnce variant
# selector and no declarative "" clear sentinel for these fields on this
# resource. This demo has been rewritten to exercise what actually exists:
#   1. full_scan_interval_minutes declared + changed (in-place update)
#   2. threshold_check_interval_minutes left UNDECLARED (not just null --
#      fully absent from the resource body) so it stays "unmanaged" per the
#      attribute contract, and must survive verbatim across an unrelated
#      update (monitor_thresholds toggle) if it's ever set out-of-band
#   3. import round-trip + drift-check
#
# Creates a brand-new, deliberately unreachable CA record (force_save=true
# bypasses Command's connectivity test on create/update) instead of touching
# any of the lab's real CA connections (e.g. id 2, "OpenBao PKI", which has
# a live schedule and associated certificates).
#
# ADDITIONAL PROVIDER BUG confirmed against kfclab (Command 25.5,
# 2026-08-08): `make destroy` reliably fails after step4/step5 run, with
# "Error clearing CA scan schedules before delete. ... 0xA011000F: Fields
# for OAuth and Client Certificate Authentication cannot both be provided
# for the same CA." Root cause: Delete()'s "clear scan schedules, then
# retry delete" fallback (resource_keyfactor_certificate_authority.go,
# triggered whenever Command reports the CA has an associated periodic
# task) rebuilds the PUT request from prior STATE via buildCARequest(), but
# that state carries residual empty-but-non-null OAuth fields (token_url/
# client_id/scope/etc, all Computed) alongside the real Client Certificate
# auth this demo actually uses -- Command rejects a PUT that sets both.
# The lifecycle target works around this by always attempting `destroy`
# regardless of step3/4/5 outcomes (so it never masks the step4/step5
# results) but does NOT itself work around the Delete() bug; if it
# reproduces, clean up the orphaned CA manually via a raw API PUT (clear
# FullScan/IncrementalScan/ThresholdCheck to null, resupply
# AuthCertificate/AuthCertificatePassword) followed by DELETE
# /CertificateAuthority/{id}.
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
  # "undeclared/unmanaged" -- this is what lets step5 seed an out-of-band
  # value and prove it survives an unrelated update (monitor_thresholds
  # toggle) verbatim.
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
