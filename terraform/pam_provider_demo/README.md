# pam_provider_demo

Full lifecycle demo for `keyfactor_pam_provider` against the lab's real
Hashicorp-Vault PAM provider type.

## What it covers

- `data.keyfactor_pam_provider_type` (Hashicorp-Vault)
- `keyfactor_pam_provider` (`remote = true` — the lab's Vault/OpenBao PAM
  provider runs on the Universal Orchestrators, not centrally in Command)
- `data.keyfactor_pam_provider` readback assertion

## Required variables

| Variable | Default | Description |
|---|---|---|
| `TF_VAR_vault_token` | none (required) | Vault token for the secret parameter. Write-only — Command never returns it. |
| `vault_host` | `https://openbao.lab.local` | Lab's OpenBao/Vault instance. |
| `vault_path_prefix` | `secret/kfclab` | Secret path prefix. |

`terraform validate` does not require `vault_token`; `apply` does.

## Known lab constraint

Parameter ordering (`parameters[0]`/`[1]`/`[2]`) assumes the Hashicorp-Vault
PAM provider type's parameters are `Host`, `Token`, `Path` in that order —
confirm against the live lab during the run phase (`data
.keyfactor_pam_provider_type.vault.parameters` output) and adjust indices if
the type's parameter order differs.

## Running

```sh
make build
make init
TF_VAR_vault_token=... make lifecycle
```
