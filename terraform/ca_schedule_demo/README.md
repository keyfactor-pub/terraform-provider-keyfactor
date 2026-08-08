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
  update (fix #193 — confirmed working), import round-trip, CA deletion when
  the CA carries an active schedule (fix #194 — confirmed working, no more
  OAuth/Client-Certificate auth field mixing on the clear-schedules-before-
  delete fallback).
- Known gaps, not part of this demo's overall pass/fail signal but each
  clearly labeled when they reproduce:
  - A Weekly-shaped schedule still crashes every `terraform` command that
    reads the CA (SDK issue #185, unrelated to #193/#194) — step5 exists
    specifically to keep surfacing this.
  - Declaring `threshold_check_daily_time` directly via Terraform config
    (step6) currently fails with "Provider produced inconsistent result
    after apply" — Command normalizes a Daily schedule's date to "today"
    server-side while keeping only the user's time-of-day, which the
    provider cannot echo back exactly. Confirmed 2026-08-08; a genuine gap
    in the new declarative *_daily_time path, separate from the
    out-of-band-preservation half of fix #193 (which does work).

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
