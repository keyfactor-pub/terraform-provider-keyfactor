# security_role_demo

End-to-end lifecycle of the legacy `keyfactor_role` resource, proving
out-of-band drift detection on Read.

## What it covers

- `keyfactor_role` create, import, reconcile, drift-check, destroy.
- `data.keyfactor_role` readback.
- `lab-oob-drift`: regression proof that mutating a role's permissions
  directly via the Command REST API (bypassing Terraform) is detected as
  drift by `terraform plan`, instead of a false "No changes."

## Running

```sh
make build
make init
make lifecycle
make lab-oob-drift   # separate regression-proof target
```

See also `security_role_permissions_demo/` for the companion
permissions-omitted-on-update regression proof (a different fix, same
underlying resource).
