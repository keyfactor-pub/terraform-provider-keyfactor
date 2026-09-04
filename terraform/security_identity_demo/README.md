# security_identity_demo

End-to-end lifecycle of the legacy `keyfactor_identity` resource (Active
Directory identities only).

## What it covers

- `keyfactor_identity` create, import, reconcile, drift-check, destroy.
- `data.keyfactor_identity` readback.
- `lab-omit-roles-update`: regression proof that omitting `roles` from
  config on an Update preserves the identity's existing role assignments
  instead of crashing with "Provider produced inconsistent result after
  apply."

## Known lab constraint

`keyfactor_identity` manages **Active Directory identities only**. kfclab is
Authentik-OAuth-only with no AD backend, so `apply` fails at Create with HTTP
400 "This operation only supports Active Directory identities" for any
account name: a structural lab gap, not a provider defect.

`make lifecycle` defaults `SKIP_LAB_AD=1`: it prints `SKIPPED: ...` and exits
0 without touching the lab. Set `SKIP_LAB_AD=0` and `ACCOUNT_NAME` to a real
AD-backed lab account to exercise this demo end-to-end.

## Running

```sh
make build
make init
make lifecycle                                    # SKIPPED by default (no AD in kfclab)
make SKIP_LAB_AD=0 ACCOUNT_NAME='DOMAIN\user' lifecycle   # against an AD-backed lab
```
