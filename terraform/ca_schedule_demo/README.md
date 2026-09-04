# ca_schedule_demo

`keyfactor_certificate_authority` CA-schedule lifecycle validation: Interval
schedule updates, out-of-band preservation of an undeclared Interval-shaped
schedule attribute across an unrelated update, the known gap where an
out-of-band Daily-shaped schedule is not preserved (the Daily variant is not
modeled by this provider release), and the still-open Weekly variant
deserialization gap (SDK issue #185).

Creates a brand-new, deliberately unreachable CA (`force_save = true`)
instead of touching any of the lab's real CA connections — see `main.tf`'s
header comment for the full design rationale, and `GNUmakefile`'s header for
the exact step-by-step variant walk.

## What it covers

- `keyfactor_certificate_authority`: Interval schedule in-place update,
  out-of-band Interval-shaped schedule preservation across an unrelated
  update (confirmed working), import round-trip, CA deletion when the CA
  carries an active schedule (fix #194 — confirmed working, no more
  OAuth/Client-Certificate auth field mixing on the
  clear-schedules-before-delete fallback).
- Known gaps, not part of this demo's overall pass/fail signal but clearly
  labeled when they reproduce:
  - An out-of-band Daily-shaped schedule is wiped to null by the very next
    unrelated `terraform apply` — this provider release only models the
    Interval variant of Command's scan/threshold schedules — step4 exists
    to keep surfacing this.
  - A Weekly-shaped schedule still crashes every `terraform` command that
    reads the CA (SDK issue #185) — step5 exists specifically to keep
    surfacing this.

## Known lab constraint

Some Command instances reject `PUT /CertificateAuthority` (Update) for any
HTTPS CA lacking an Authentication Certificate, even under `forceSave=true`.
`authcert.pfx` is a throwaway self-signed cert generated solely to satisfy
this — never used for real authentication, never committed (gitignored).
Not yet confirmed whether kfclab's Command has the same requirement.

## Variables

See `variables.tf` — `suffix`, `host_name`, `full_scan_interval_minutes`,
`incremental_scan_interval_minutes`, `monitor_thresholds`,
`auth_certificate_password`.

## Running

```sh
make build
make authcert   # generate throwaway authcert.pfx (one-time, gitignored)
make init
make lifecycle
```
