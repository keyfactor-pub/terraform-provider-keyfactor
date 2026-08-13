# ca_schedule_demo

`keyfactor_certificate_authority` CA-schedule lifecycle validation: Interval
schedule updates, out-of-band preservation of an undeclared schedule
attribute across an unrelated update (both Interval- and Daily-shaped, fix
#193), the Daily variant declared directly via Terraform config (also fix
#193), and the still-open Weekly variant deserialization gap (SDK issue
#185, unrelated to #193/#194).

Creates a brand-new, deliberately unreachable CA (`force_save = true`)
instead of touching any of the lab's real CA connections — see `main.tf`'s
header comment for the full design rationale, and `GNUmakefile`'s header for
the exact step-by-step variant walk.

## What it covers

- `keyfactor_certificate_authority`: Interval schedule in-place update,
  out-of-band Interval/Daily schedule preservation across an unrelated
  update (fix #193 — confirmed working), the Daily variant declared directly
  via Terraform config as a bare UTC time-of-day, `"HH:MM:SS"` (also fix
  #193 — the attribute's wire format drops the date component entirely
  since Command rewrites it to "today" server-side regardless of what is
  sent, so only the time-of-day is ever compared), import round-trip, CA
  deletion when the CA carries an active schedule (fix #194 — confirmed
  working, no more OAuth/Client-Certificate auth field mixing on the
  clear-schedules-before-delete fallback).
- Known gap, not part of this demo's overall pass/fail signal but clearly
  labeled when it reproduces:
  - A Weekly-shaped schedule still crashes every `terraform` command that
    reads the CA (SDK issue #185, unrelated to #193/#194) — step5 exists
    specifically to keep surfacing this.

## Known lab constraint

Some Command instances reject `PUT /CertificateAuthority` (Update) for any
HTTPS CA lacking an Authentication Certificate, even under `forceSave=true`.
`authcert.pfx` is a throwaway self-signed cert generated solely to satisfy
this — never used for real authentication, never committed (gitignored).
Not yet confirmed whether kfclab's Command has the same requirement.

## Variables

See `variables.tf` — `suffix`, `host_name`, `full_scan_interval_minutes`,
`incremental_scan_interval_minutes`, `threshold_check_daily_time`,
`monitor_thresholds`, `auth_certificate_password`.

## Running

```sh
make build
make authcert   # generate throwaway authcert.pfx (one-time, gitignored)
make init
make lifecycle
```
