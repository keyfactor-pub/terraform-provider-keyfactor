# pam_provider_type_demo

Full-lifecycle smoke test for `keyfactor_pam_provider_type`, proving the
`parameters[].data_type` create/read/import round-trip.

## What it covers

- `keyfactor_pam_provider_type` create, import, reconcile, drift-check, destroy.

## Variables

See `variables.tf` — `suffix`.

## Running

```sh
make build
make init
make lifecycle
```

See also `pam_provider_demo/` for the companion `keyfactor_pam_provider`
resource against the lab's real Hashicorp-Vault PAM provider type.
