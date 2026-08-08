# store_container_demo

Validates that `container_name` (pre-v25 style) and `application_name`
(v25+ alias) are interchangeable on `keyfactor_certificate_store` resources —
both link the store to the same Keyfactor application/container without
forcing resource replacement.

A third store (`repro175`, see `repro175.tf`) reproduces
[GitHub issue #175](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/175):
`Update()` silently clears a container assignment made out-of-band whenever
config never declares `application_name`/`container_name`.

## What it covers

- `keyfactor_application` + 2x `keyfactor_certificate_store`
  (`container_name` vs `application_name` styles).
- `data.keyfactor_certificate_store` readback assertion.
- `repro175`: standalone reproduction sequence for issue #175 (seed →
  unrelated update → verify), independent of the main `lifecycle`.

## Variables

See `variables.tf` — `suffix`, `namespace`, `inventory_schedule`,
`create_if_missing`, `k8s_server_password_file`, `repro175_inventory_schedule`.

kfclab's K8S orchestrators use in-cluster pod-identity auth by default (no
kubeconfig needed — see `stores.tf`). Only set `k8s_server_password_file`
for orchestrators without that RBAC binding.

## Running

```sh
make build
make init
make lifecycle     # container_name / application_name interchangeability
make repro175      # standalone issue #175 reproduction
```
