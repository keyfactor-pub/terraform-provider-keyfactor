# Certificate Collection Demo

End-to-end lifecycle demonstration of the `keyfactor_certificate_collection`
resource (added in v2.10), plus its companion `keyfactor_certificate_collection`
data source: create a collection, update its description and query in place,
import it by numeric ID, verify zero drift, and destroy it.

## Prerequisites

| Requirement | Details |
|---|---|
| Go ≥ 1.21 | Required to build the provider |
| Terraform ≥ 1.3 | CLI must be on `$PATH` |
| Python 3 | Used by `_export_ids.py` |
| Keyfactor Command | OAuth credentials required |

### Environment variables

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
| `main.tf` | Provider config, the `keyfactor_certificate_collection` resource, its data source readback, and outputs |
| `variables.tf` | Input variables (`suffix`, `description_override`, `query_override`) |
| `.terraformrc` | Dev override pointing Terraform at the locally built provider binary |
| `GNUmakefile` | All workflow targets |
| `tf_state.json` | **Generated**, captured from `terraform show -json` |
| `_import_pairs.txt` | **Generated**, `tf_name id` pairs used by `import-all` |

## What it covers

- `keyfactor_certificate_collection` create, in-place update, import by
  numeric ID, drift-check, destroy.
- `data.keyfactor_certificate_collection` readback by name, asserted against
  the resource's own state via the `datasource_readback_matches` output.
- The `query` attribute is not returned by `GetById`, so it's a write-only
  field from the provider's perspective: `reconcile` re-applies the config
  after import to settle it, and `lab-update` changes `query` (not just
  `description`) to exercise the update path end to end.

## Quickstart

```bash
# 1. Build and install the provider locally
make build

# 2. Initialize Terraform
make init

# 3a. Full lifecycle using lab credentials from ~/.env_kfclab (recommended)
make lifecycle

# 3b. Or run individual steps against your own environment
make apply
make import-all
make reconcile
make drift-check
make destroy

# 4. Use a custom name suffix to avoid conflicts
make all SUFFIX=_STAGING
```

## Individual targets

```
make build          Compile and install provider to ~/go/bin
make init           terraform init
make validate       terraform validate
make plan           terraform plan
make apply          terraform apply -auto-approve
make import-all     Capture state, remove the collection, re-import by numeric ID
make reconcile      terraform apply -auto-approve (settles the write-only `query` field post-import)
make drift-check    terraform plan; should show "No changes" after reconcile
make destroy        terraform destroy -auto-approve
make clean          Remove generated files (tf_state.json, _import_pairs.txt, etc.)
```

### Lab convenience targets

These targets source `KEYFACTOR_ENV_FILE` (default: `~/.env_kfclab`) automatically.

```
make lifecycle          Full test: apply → update → import-all → reconcile → drift-check → destroy
make lab-plan           Plan using lab credentials
make lab-apply          Apply using lab credentials
make lab-update         Change description + query in place, verify, then revert to defaults
make lab-import-all     Import the collection using lab credentials
make lab-reconcile      Reconcile (re-apply) using lab credentials
make lab-drift-check    Drift-check using lab credentials
make lab-destroy        Destroy using lab credentials
```

Override any lab setting on the command line:

```bash
make KEYFACTOR_ENV_FILE=~/.env_prod SUFFIX=_STAGING lifecycle
```

## How it works

1. **`make apply`** creates one `keyfactor_certificate_collection` with a
   fixed query, plus a data source that reads it back by name.

2. **`make lab-update`** sets `description_override` and `query_override` to
   new values, applies, and plans (expect "No changes"), then reverts to the
   defaults and repeats. This proves both fields update in place rather than
   forcing a replace.

3. **`make import-all`** captures `terraform show -json` → `tf_state.json`,
   runs `_export_ids.py` to extract the `tf_name → numeric_id` pair, removes
   the resource from state, then re-imports it by its integer ID.

4. **`make reconcile`** runs `terraform apply` immediately after import. The
   Command API's `GetById` response does not include `query`, so the
   provider cannot populate it purely from a Read; reconcile resupplies the
   configured value.

5. **`make drift-check`** runs `terraform plan` and should report
   `No changes`, proving that the imported and reconciled state matches the
   configuration.

6. **`make destroy`** deletes the collection from the Command instance.

## Import identifier

Certificate collections are imported by their **integer ID** (not name):

```bash
terraform import keyfactor_certificate_collection.demo 42
```

The `_export_ids.py` script automates this: it reads the Terraform state
JSON and writes the `tf_name id` line to `_import_pairs.txt`, which
`import-all` then consumes.
