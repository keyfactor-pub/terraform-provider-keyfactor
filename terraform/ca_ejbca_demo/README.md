# ca_ejbca_demo

`keyfactor_certificate_authority` create+update lifecycle demo for an HTTPS /
AnyCA REST Gateway connection (`ca_type = 1`), exercising the OAuth connector
fields: `client_id`, `client_secret`, `token_url`, `scope`, `audience`.

## What it covers

- `keyfactor_certificate_authority` (ca_type=1) create, update (scope/audience
  rotation), import, drift-check, destroy.
- `data.keyfactor_certificate_authority` readback assertion.

This registers a **separate** CA connection record pointed at the same
gateway host as the lab's real "OpenBao PKI" CA (id 2) — it never touches or
duplicates that CA's actual configuration.

## Required variables (no defaults — never commit real values)

| Variable | Description |
|---|---|
| `TF_VAR_ca_client_id` | OAuth client_id for the AnyCA REST Gateway connector. |
| `TF_VAR_ca_client_secret` | OAuth client_secret. Sensitive. |
| `TF_VAR_ca_token_url` | OAuth token endpoint URL. |

`terraform validate` does not require these; `apply` does.

## Known lab constraint

If the target gateway requires an Authentication Certificate for HTTPS CA
PUTs (some Command instances do — see `ca_schedule_demo`'s header for a
worked example of that constraint), this demo's `lab-update` step may need
`auth_certificate`/`auth_certificate_password` added. Not yet confirmed
against kfclab; check during the live-lab run phase.

## Running

```sh
make build
make init
make validate
TF_VAR_ca_client_id=... TF_VAR_ca_client_secret=... TF_VAR_ca_token_url=... make lifecycle
```
