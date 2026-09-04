# security_role_permissions_demo

End-to-end lifecycle of the legacy `keyfactor_role` resource, proving that
omitting `permissions` from config on an unrelated Update preserves the
role's existing permissions instead of crashing with "Provider produced
inconsistent result after apply."

This is a separate demo from `security_role_demo/` (which proves a different
fix: out-of-band drift detection).

## What it covers

- `keyfactor_role` create, import, reconcile, drift-check, destroy.
- `lab-omit-permissions-update`: the regression proof described above.

## Running

```sh
make build
make init
make lifecycle
make lab-omit-permissions-update   # separate regression-proof target
```
