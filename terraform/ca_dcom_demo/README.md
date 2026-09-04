# ca_dcom_demo

Record-only demo for a DCOM (`ca_type = 0`) `keyfactor_certificate_authority`
registration.

## What it covers

- `keyfactor_certificate_authority` create/import/destroy for a DCOM-style
  Windows AD CS connection record, using fabricated (never real) host/forest
  values.

## Known lab constraint

kfclab is an Authentik-OAuth-only lab with no Active Directory / DCOM CA
backend. This demo may either:

- succeed as a pure metadata record (Command does not always network-probe
  DCOM connections the way it does HTTPS CAs), or
- be rejected outright if this Command instance validates DCOM records more
  strictly.

`make lifecycle` treats a Create failure here as a clean `SKIPPED` (exit 0),
not a harness failure; this demo exists to document the constraint.

## Variables

| Variable | Default | Description |
|---|---|---|
| `suffix` | `_TF` | Appended to the CA's logical_name. |
| `host_name` | `fake-dcom-ca.example.lab` | Fictitious, unreachable AD CS host. |
| `forest_root` | `example.lab` | Fictitious AD forest root / configuration tenant. |

## Running

```sh
make build
make init
make lifecycle
```
