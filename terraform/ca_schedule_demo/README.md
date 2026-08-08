# ca_schedule_demo

`keyfactor_certificate_authority` CA-schedule lifecycle validation: schedule
variant switching (Interval → Daily), the declarative clear sentinel,
out-of-band drift detection, and unmodeled-schedule-variant (Weekly/Monthly)
preservation across an unrelated update.

Creates a brand-new, deliberately unreachable CA (`force_save = true`)
instead of touching any of the lab's real CA connections — see `main.tf`'s
header comment for the full design rationale, and `GNUmakefile`'s header for
the exact step-by-step variant walk.

## What it covers

- `keyfactor_certificate_authority`: Interval schedule, Daily schedule,
  declarative clear sentinel, out-of-band re-add + drift detection,
  unrelated-update schedule preservation, import round-trip.

## Known lab constraint

Some Command instances reject `PUT /CertificateAuthority` (Update) for any
HTTPS CA lacking an Authentication Certificate, even under `forceSave=true`.
`authcert.pfx` is a throwaway self-signed cert generated solely to satisfy
this — never used for real authentication, never committed (gitignored).
Not yet confirmed whether kfclab's Command has the same requirement.

## Variables

See `variables.tf` — `suffix`, `host_name`, `full_scan_interval_minutes`,
`full_scan_daily_time`, `monitor_thresholds`, `auth_certificate_password`.

## Running

```sh
make build
make authcert   # generate throwaway authcert.pfx (one-time, gitignored)
make init
make lifecycle
```
