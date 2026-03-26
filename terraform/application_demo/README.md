# Application Demo

End-to-end demonstration of the `keyfactor_application` resource: create seven
applications covering every inventory schedule type, import them by numeric ID,
verify zero drift, and destroy.

> **Note:** Applications require Keyfactor Command v25.0+.

## Prerequisites

| Requirement | Details |
|---|---|
| Go ≥ 1.21 | Required to build the provider |
| Terraform ≥ 1.3 | CLI must be on `$PATH` |
| Python 3 | Used by `_export_ids.py` |
| Keyfactor Command ≥ v25.0 | OAuth credentials required |

## Files

| File | Purpose |
|---|---|
| `main.tf` | Provider config and outputs |
| `applications.tf` | Seven `keyfactor_application` resources (one per schedule type) |
| `variables.tf` | Input variables (suffix, interval_minutes, daily_time) |
| `_export_ids.py` | Reads `tf_state.json`, writes `_import_pairs.txt` for `terraform import` |
| `.terraformrc` | Dev override pointing Terraform at the locally built provider binary |
| `GNUmakefile` | All workflow targets |
| `tf_state.json` | **Generated** — captured from `terraform show -json` |
| `_import_pairs.txt` | **Generated** — `tf_name id` pairs used by `import-all` |

### Environment variables

```bash
export KEYFACTOR_HOSTNAME=your-command-host.example.com
export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token

# Optional — skip TLS verification for self-signed certs
export KEYFACTOR_SKIP_VERIFY=true
```

> **Note:** If `KEYFACTOR_USERNAME` / `KEYFACTOR_PASSWORD` are also set, the
> provider will prefer basic auth over OAuth. Unset them if you want OAuth.

## Quickstart

```bash
# 1. Build and install the provider locally
make build

# 2. Initialize Terraform
make init

# 3a. Full lifecycle using lab credentials from ~/.env_ses2541 (recommended)
make lifecycle

# 3b. Or set env vars manually and run individual steps
make apply
make import-all
make reconcile     # re-apply to settle schedule_immediate / schedule_exactly_once drift
make drift-check   # should show "No changes"
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
make import-all     Capture state, remove resources, re-import each by numeric ID
make reconcile      terraform apply -auto-approve (settles immediate/exactly-once drift post-import)
make drift-check    terraform plan — should show "No changes" after reconcile
make destroy        terraform destroy -auto-approve
make clean          Remove generated files (tf_state.json, _import_pairs.txt, etc.)
```

### Lab convenience targets

These targets source `LAB_ENV_FILE` (default: `~/.env_ses2541`) automatically.

```
make lifecycle          Full test: apply → update → import-all → reconcile → drift-check → destroy
make lab-plan           Plan using lab credentials
make lab-apply          Apply using lab credentials
make lab-update         Update interval_minutes + daily_time; verify in-place update; revert to defaults
make lab-import-all     Import all applications using lab credentials
make lab-reconcile      Reconcile (re-apply) using lab credentials
make lab-drift-check    Drift-check using lab credentials
make lab-destroy        Destroy using lab credentials
```

Override any lab setting on the command line:

```bash
make LAB_ENV_FILE=~/.env_prod SUFFIX=_STAGING lifecycle
```

### lab-update detail

`make lab-update` runs two steps:

1. **Update**: sets `interval_minutes=30` and `daily_time="2025-01-01T08:00:00Z"`; applies; plans (expect "No changes").
2. **Revert**: restores defaults (`interval_minutes=60`, `daily_time="2025-01-01T23:30:00Z"`); applies; plans (expect "No changes").

Both steps verify in-place update — no application should be destroyed and re-created.

## How it works

1. **`make apply`** creates seven applications on the Command instance covering
   every schedule type: no schedule, immediate, interval, daily, weekly, monthly,
   and exactly-once.

2. **`make import-all`** captures `terraform show -json` → `tf_state.json`,
   runs `_export_ids.py` to extract `tf_name → numeric_id` pairs, removes
   every managed resource from state, then re-imports each one by its integer ID.

3. **`make reconcile`** runs `terraform apply` immediately after import. This
   settles any drift from `schedule_immediate` (server may convert to ExactlyOnce
   after the job fires) and `schedule_exactly_once_time` (server clears it once fired).

4. **`make drift-check`** runs `terraform plan` and should report `No changes`,
   proving that the imported and reconciled state matches the configuration.

5. **`make destroy`** deletes all seven applications from the Command instance.

## Resource overview

| Terraform name | Application name | Schedule |
|---|---|---|
| `keyfactor_application.no_schedule` | `Demo No Schedule<SUFFIX>` | None |
| `keyfactor_application.immediate` | `Demo Immediate<SUFFIX>` | Immediate (one-shot) |
| `keyfactor_application.interval_schedule` | `Demo Interval Schedule<SUFFIX>` | Every `interval_minutes` min (default 60) |
| `keyfactor_application.daily_schedule` | `Demo Daily Schedule<SUFFIX>` | Daily at `daily_time` (default 23:30 UTC) |
| `keyfactor_application.weekly_schedule` | `Demo Weekly Schedule<SUFFIX>` | Weekly Mon+Thu at 02:00 UTC |
| `keyfactor_application.monthly_schedule` | `Demo Monthly Schedule<SUFFIX>` | Monthly on day 1 at 04:00 UTC |
| `keyfactor_application.exactly_once` | `Demo Exactly Once<SUFFIX>` | Once at 2025-06-01T06:00:00Z (one-shot) |

> **One-shot schedules:** `schedule_immediate` and `schedule_exactly_once_time`
> are one-shot triggers — after the job fires the server clears the schedule.
> Subsequent plans show drift until `make reconcile` re-applies the config.

## Import identifier

Applications are imported by their **integer ID** (not name):

```bash
terraform import keyfactor_application.no_schedule 42
```

The `_export_ids.py` script automates this — it reads the Terraform state JSON
and writes one `tf_name id` line per application to `_import_pairs.txt`, which
`import-all` then iterates.

## Assigning certificate stores

Certificate stores are assigned to an application by setting `container_name`
on the `keyfactor_certificate_store` resource:

```hcl
resource "keyfactor_certificate_store" "example" {
  # ... other store config ...
  container_name = keyfactor_application.interval_schedule.name
}
```

The `store_count` output reflects how many stores are currently assigned to
each application.
