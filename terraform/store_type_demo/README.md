# Store Type Demo

End-to-end demonstration of the `keyfactor_certificate_store_type` resource and
`keyfactor_certificate_store_types` data source: discover all store types from a
live Command instance, generate Terraform resources for each one (with a
configurable suffix), create them, import them, verify zero drift, and destroy.

## Prerequisites

| Requirement | Details |
|---|---|
| Go ≥ 1.21 | Required to build the provider |
| Terraform ≥ 1.3 | CLI must be on `$PATH` |
| Python 3 | Used by `gen_store_types.py` |
| Keyfactor Command ≥ v11 | OAuth credentials required |

### Environment variables

Set these before running any `make` target (or source your env file):

```bash
export KEYFACTOR_HOSTNAME=your-command-host.example.com
export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token

# Optional: skip TLS verification for self-signed certs
export KEYFACTOR_SKIP_VERIFY=true
```

> **Note:** If `KEYFACTOR_USERNAME` / `KEYFACTOR_PASSWORD` are also set, the
> provider will prefer basic auth over OAuth. Unset them if you want OAuth.

## Files

| File | Purpose |
|---|---|
| `main.tf` | Provider config + data source that discovers all store types |
| `store_types.tf` | **Generated**: one `keyfactor_certificate_store_type` resource per discovered type |
| `gen_store_types.py` | Python generator: reads `tf_state.json`, emits `store_types.tf` |
| `.terraformrc` | Dev override pointing Terraform at the locally built provider binary |
| `GNUmakefile` | All workflow targets |
| `tf_state.json` | **Generated**: captured from `terraform show -json` |

## Quickstart

```bash
# 1. Build and install the provider locally
make build

# 2. Initialize Terraform
make init

# 3. Run the full workflow (build → validate → apply → import → drift-check → destroy)
make all

# 4. Use a custom suffix
make all SUFFIX=_STAGING
```

## Individual targets

```
make build          Compile and install provider to ~/go/bin
make init           terraform init
make validate       terraform validate
make apply-data     Apply data sources only (discovers store types)
make generate       Capture state + run gen_store_types.py → store_types.tf
make plan           terraform plan (requires store_types.tf to exist)
make apply          terraform apply -auto-approve
make import-all     Remove all resources from state, then re-import by short_name
make drift-check    terraform plan: should show "No changes" after import
make destroy        terraform destroy -auto-approve
make clean          Remove generated files (tf_state.json, store_types.tf, etc.)
```

### Lab convenience targets

These targets source `KEYFACTOR_ENV_FILE` (default: `~/.env_kfclab`) automatically.

```
make lifecycle          Full test: generate → apply → update (idempotency) → import-all → drift-check → destroy
make lab-generate       Discover store types and generate store_types.tf using lab credentials
make lab-plan           Plan using lab credentials
make lab-apply          Apply using lab credentials
make lab-update         Re-apply to verify idempotency, then plan (should show "No changes")
make lab-import-all     Import all store types using lab credentials
make lab-drift-check    Drift-check using lab credentials
make lab-destroy        Destroy using lab credentials
```

Override any lab setting on the command line:

```bash
make KEYFACTOR_ENV_FILE=~/.env_prod SUFFIX=_STAGING lifecycle
```

## How it works

1. **`make apply-data`** runs `terraform apply` on the data-source-only config,
   which calls `GET /CertificateStoreTypes` (paginated) and returns all store types.

2. **`make generate`** captures `terraform show -json` → `tf_state.json`, then
   calls `gen_store_types.py` which iterates every store type and emits a
   `keyfactor_certificate_store_type` resource block with the configured suffix
   appended to `name`, `short_name`, and `capability`.

3. **`make apply`** creates all generated resources on the Command instance.

4. **`make import-all`** removes every managed resource from the Terraform state,
   then re-imports each one using its `short_name` as the import identifier.
   This validates that `terraform import` works for every store type variant.

5. **`make drift-check`** runs `terraform plan` and asserts `No changes`, proving
   that the imported state exactly matches the generated configuration.

6. **`make destroy`** deletes all created store types from the Command instance.

## Customising the generator

```bash
# Use a different suffix
python3 gen_store_types.py --suffix _DEV

# Read from a different state file
python3 gen_store_types.py --state /path/to/other_state.json

# Write to a different output file
python3 gen_store_types.py --out /path/to/output.tf
```

Run `python3 gen_store_types.py --help` for all options.
