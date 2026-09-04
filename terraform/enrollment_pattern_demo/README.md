# Enrollment Pattern Demo

End-to-end lifecycle demonstration of the `keyfactor_enrollment_pattern`
resource (added in v2.10), plus its companion `keyfactor_enrollment_pattern`
data source: create a pattern tied to a certificate template, update its
associated role, owner role, and restricted CA in place, import it by numeric
ID, verify zero drift, and destroy it.

> **Note:** Enrollment patterns require Keyfactor Command v25.0+.

## Prerequisites

| Requirement | Details |
|---|---|
| Go ≥ 1.21 | Required to build the provider |
| Terraform ≥ 1.3 | CLI must be on `$PATH` |
| Python 3 | Used by `_export_ids.py` |
| Keyfactor Command ≥ v25.0 | OAuth credentials required |

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
| `main.tf` | Provider config, template/role/CA data source lookups, the `keyfactor_enrollment_pattern` resource, its data source readback, and outputs |
| `variables.tf` | Input variables (`template_name`, `suffix`, `description_override`, `associated_role_name`, `owner_role_name`, `ca_name`) |
| `.terraformrc` | Dev override pointing Terraform at the locally built provider binary |
| `GNUmakefile` | All workflow targets |
| `tf_state.json` | **Generated**, captured from `terraform show -json` |
| `_import_pairs.txt` | **Generated**, `tf_name id` pairs used by `import-all` |

## What it covers

- `keyfactor_enrollment_pattern` create, in-place update, import by numeric
  ID, drift-check, destroy.
- `data.keyfactor_enrollment_pattern` readback by name, asserted against the
  resource's own state via the `datasource_readback_matches` output.
- `associated_role_names` and `certificate_authority_ids` are modeled as
  Terraform sets and are always derived from Command's own expansion
  (`associated_roles`/`certificate_authorities`) on every refresh, rather
  than preserved from prior config, so a real change made outside Terraform
  would still surface as drift, while re-submitting the same members never
  does.
- `lab-update` changes `associated_role_name`, `owner_role_name`, and
  `ca_name` (not just `description`) to exercise the update path for
  `associated_role_names`, `certificate_authority_ids`, and
  `policies.default_certificate_owner_role_id` end to end.

`force_template_default` is deliberately not exercised by this demo: setting
it would steal `TemplateDefault` status from kfclab's shared seed pattern for
the demo's template, which would break this demo's own `destroy` step and
leave other demos/tests without their expected default pattern. That
attribute is covered instead by a dedicated Go unit test
(`resource_keyfactor_enrollment_pattern_mirror_fix_unit_test.go`).

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
make import-all     Capture state, remove the pattern, re-import by numeric ID
make reconcile      terraform apply -auto-approve (settles any remaining Computed-only fields post-import)
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
make lab-update         Change associated_role_name/owner_role_name/ca_name + description in place, verify, then revert to defaults
make lab-import-all     Import the pattern using lab credentials
make lab-reconcile      Reconcile (re-apply) using lab credentials
make lab-drift-check    Drift-check using lab credentials
make lab-destroy        Destroy using lab credentials
```

Override any lab setting on the command line:

```bash
make KEYFACTOR_ENV_FILE=~/.env_prod SUFFIX=_STAGING lifecycle
```

## How it works

1. **`make apply`** looks up a certificate template, two security roles, and
   a certificate authority via data sources, then creates one
   `keyfactor_enrollment_pattern` restricted to that CA and role, plus a data
   source that reads it back by name.

2. **`make lab-update`** points `associated_role_name`, `owner_role_name`,
   and `ca_name` at different roles/CA, sets `description_override`, applies,
   and plans (expect "No changes"), then reverts to the defaults and repeats.
   This proves the resource updates `associated_role_names`,
   `certificate_authority_ids`, and `policies.default_certificate_owner_role_id`
   in place rather than forcing a replace.

3. **`make import-all`** captures `terraform show -json` → `tf_state.json`,
   runs `_export_ids.py` to extract the `tf_name → numeric_id` pair, removes
   the resource from state, then re-imports it by its integer ID.

4. **`make reconcile`** runs `terraform apply` immediately after import. This
   is typically a no-op ("No changes") because `associated_role_names` and
   `certificate_authority_ids` are derived directly from the `GetById`
   response on import.

5. **`make drift-check`** runs `terraform plan` and should report
   `No changes`, proving that the imported and reconciled state matches the
   configuration.

6. **`make destroy`** deletes the pattern from the Command instance.

## Import identifier

Enrollment patterns are imported by their **integer ID** (not name):

```bash
terraform import keyfactor_enrollment_pattern.demo 42
```

The `_export_ids.py` script automates this: it reads the Terraform state
JSON and writes the `tf_name id` line to `_import_pairs.txt`, which
`import-all` then consumes.
