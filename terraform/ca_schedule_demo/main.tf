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
# SCHEMA HISTORY: this demo was originally written against a Daily CA scan
# schedule variant model (full_scan_daily_time et al, referenced by PRs
# #173/#182/#184). That variant model was absent from the released v2.9.1
# schema -- confirmed 2026-08-07 -- so the demo was temporarily rewritten to
# exercise only the flat interval-minutes fields. Fixes #193/#194 (verified
# 2026-08-08 against a locally-built fix/harness-bugs provider) restored the
# Daily variant as *_daily_time attributes (full_scan_daily_time,
# incremental_scan_daily_time, threshold_check_daily_time), each mutually
# exclusive with its *_interval_minutes sibling and enforced by
# ValidateConfig. This demo now exercises:
#   1. full_scan_interval_minutes declared + changed (in-place update)
#   2. threshold_check_interval_minutes left UNDECLARED (not just null --
#      fully absent from the resource body) so it stays "unmanaged" per the
#      attribute contract, and must survive verbatim across an unrelated
#      update (monitor_thresholds toggle) if it's ever set out-of-band
#      (step3), including when the out-of-band value is Daily-shaped, not
#      just Interval-shaped (step4 -- this is the #193 fix: pre-fix, a
#      Daily-shaped schedule read back as null and got silently wiped by the
#      very next unrelated apply)
#   3. threshold_check_daily_time declared directly via Terraform config
#      (step6) -- testing whether the new Daily variant round-trips when
#      actually managed declaratively, not just preserved when set
#      out-of-band. It currently does NOT (see the resource block below and
#      step6-apply-daily's header for the date-normalization gap found here)
#   4. import round-trip + drift-check
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
  # "undeclared/unmanaged" -- this is what lets step5 seed an out-of-band
  # value and prove it survives an unrelated update (monitor_thresholds
  # toggle) verbatim.
  #
  # threshold_check_daily_time, by contrast, IS declared -- via a variable
  # that defaults to null. A `var.x = null` reference is indistinguishable
  # from a fully-absent attribute in the raw config the provider sees (both
  # produce a null config value), so this does not disturb the
  # undeclared/unmanaged behavior above at all when the var is left at its
  # default. Setting TF_VAR_threshold_check_daily_time to a real RFC3339
  # timestamp (see step6-* in GNUmakefile) is what exercises the new
  # full_scan_daily_time/incremental_scan_daily_time/threshold_check_daily_time
  # attribute pair declaratively.
  #
  # RESULT (verified live against kfclab, 2026-08-08, locally built
  # fix/harness-bugs provider): this does NOT round-trip on first apply.
  # Command normalizes a Daily schedule's Time to a server-side DATE (the
  # date the schedule was written) while preserving only the user-supplied
  # time-of-day; buildSchedule/scheduleToState send and echo back a full
  # RFC3339 timestamp, so a value with any other date than "today" always
  # comes back changed -- e.g. declaring "2026-01-01T04:15:00Z" comes back
  # as "2026-08-08T04:15:00Z" (today's date, same time-of-day), which
  # Terraform correctly flags as "Provider produced inconsistent result
  # after apply" since this attribute is Optional but not Computed. This is
  # a genuine gap in the new declarative *_daily_time path specifically --
  # separate from (and not fixed by) the out-of-band-preservation fix step4
  # exercises, which DOES work correctly. See step6-apply-daily.
  threshold_check_daily_time = var.threshold_check_daily_time
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

output "threshold_check_daily_time" {
  description = "threshold_check_daily_time as read back into state. Null unless TF_VAR_threshold_check_daily_time is set (see GNUmakefile step6-*)."
  value       = keyfactor_certificate_authority.demo.threshold_check_daily_time
}
