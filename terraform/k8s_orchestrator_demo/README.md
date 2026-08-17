# K8S Orchestrator Demo

End-to-end demonstration of `keyfactor_certificate_store` resources for all Kubernetes
store types: K8STLSSecr, K8SSecret, K8SCert, K8SJKS (+ buddy-pass variant), K8SPKCS12
(+ buddy-pass variant), K8SNS, and K8SCluster. Includes certificate enrollment,
deployment into stores, import, and zero-drift verification.

## Prerequisites

| Requirement | Details |
|---|---|
| Go ≥ 1.21 | Required to build the provider |
| Terraform ≥ 1.3 | CLI must be on `$PATH` |
| Python 3 | Used by `_export_ids.py` |
| Keyfactor Command ≥ v11 | OAuth credentials required |
| Approved K8S orchestrator | Agent must be approved and have `K8STLSSecr` capability |
| Kubeconfig JSON | Flat kubeconfig used as `server_password` for all K8S stores |

### Environment variables

```bash
# Keyfactor auth
export KEYFACTOR_HOSTNAME=your-command-host.example.com
export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token

# Optional — skip TLS verification for self-signed certs
export KEYFACTOR_SKIP_VERIFY=true

# Certificate enrollment
export TF_VAR_certificate_authority="OpenBao PKI"          # or "MyHost\\LogicalName" for Windows CAs
export TF_VAR_certificate_template="AnyCA_lab-role"

# K8S kubeconfig (path to flat JSON file used as server_password)
export TF_VAR_k8s_server_password_file=/path/to/sa-context.json
```

> **inventory_schedule caveat:** `"immediate"` is a one-shot trigger — Command removes
> the schedule once the inventory job runs (or exhausts retries). Subsequent plans show
> drift from `"immediate"` to empty. Use `"Daily at HH:MM:SS"` for a persistent schedule
> that survives re-plans. The lab convenience targets default to `"Daily at 12:00:00"`.

## Files

| File | Purpose |
|---|---|
| `main.tf` | Provider config, data sources, outputs |
| `stores.tf` | Nine `keyfactor_certificate_store` resources (one per K8S store type) |
| `deployments.tf` | `keyfactor_certificate_deployment` resources |
| `variables.tf` | Input variables (schedule, namespace, passwords, CA, template) |
| `outputs.tf` | Output values (store IDs, agent ID) |
| `_export_ids.py` | Extracts `tf_name → store_id` pairs from state JSON |
| `.terraformrc` | Dev override for the locally built provider binary |
| `GNUmakefile` | All workflow targets |

## Quickstart

```bash
# 1. Build and install the Keyfactor provider locally
make build

# 2. Initialize Terraform
make init

# 3a. Full lifecycle using lab credentials from ~/.env_kfclab (recommended)
make lifecycle

# 3b. Or set env vars manually and run individual steps
export KEYFACTOR_HOSTNAME=... # see Environment variables above
make apply
make import-all
make apply         # reconcile after import
make drift-check   # should show "No changes" (only write-only fields if any)
make destroy
```

## Individual targets

```
make build          Compile and install Keyfactor provider to ~/go/bin
make init           terraform init
make validate       terraform validate
make plan           terraform plan
make apply          Create all K8S certificate stores
make import-all     Capture state, remove stores, re-import each by store ID
make drift-check    terraform plan — should show "No changes" after import
make destroy        terraform destroy -auto-approve
make clean          Remove generated files
```

### Lab convenience targets

These targets source `KEYFACTOR_ENV_FILE` (default: `~/.env_kfclab`) automatically and use
`"Daily at 12:00:00"` for `inventory_schedule` (avoids `"immediate"` drift).

```
make lifecycle          Full test: apply → update → import-all → apply (reconcile) → drift-check → destroy
make lab-plan           Plan using lab credentials
make lab-apply          Apply using lab credentials (inventory_schedule="Daily at 12:00:00")
make lab-update         Update inventory_schedule + create_if_missing; verify in-place update + revert
make lab-import-all     Import all stores using lab credentials
make lab-drift-check    Drift-check using lab credentials
make lab-destroy        Destroy using lab credentials
```

Override any lab setting on the command line:

```bash
make KEYFACTOR_ENV_FILE=~/.env_prod lifecycle
```

### lab-update detail

`make lab-update` runs two steps:

1. **Update**: sets `inventory_schedule="Daily at 14:00:00"` and `create_if_missing=false`; applies; plans (expect "No changes").
2. **Revert**: restores `inventory_schedule="Daily at 12:00:00"` and `create_if_missing=true`; applies; plans (expect "No changes").

Both steps verify in-place update — no store should be destroyed and re-created.

## Store inventory

| Resource | Store type | Store path |
|---|---|---|
| `k8s_tls_secret` | K8STLSSecr | `<namespace>/tf-demo-tls-secret` |
| `k8s_opaque_secret` | K8SSecret | `<namespace>/tf-demo-opaque-secret` |
| `k8s_cert` | K8SCert | `<namespace>` |
| `k8s_jks` | K8SJKS | `<namespace>/tf-demo-jks` |
| `k8s_jks_buddy` | K8SJKS | `<namespace>/tf-demo-jks-buddy` (PasswordIsK8SSecret) |
| `k8s_pkcs12` | K8SPKCS12 | `<namespace>/tf-demo-pkcs12` |
| `k8s_pkcs12_buddy` | K8SPKCS12 | `<namespace>/tf-demo-pkcs12-buddy` (PasswordIsK8SSecret) |
| `k8s_ns` | K8SNS | `<namespace>` |
| `k8s_cluster` | K8SCluster | `<namespace>` |

## Import identifier

Stores are imported by their **store ID** (UUID):

```bash
terraform import keyfactor_certificate_store.k8s_tls_secret "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

## Deployment alias formats

| Store type | Alias format | Notes |
|---|---|---|
| K8STLSSecr / K8SSecret | *(none required)* | Cert placed into backing secret by store path |
| K8SJKS | `jks/<keystore-alias>` | Field name `jks` set via `CertificateDataFieldName` |
| K8SPKCS12 | `.p12/<keystore-alias>` | Field name `.p12` set via `CertificateDataFieldName` |
| K8SCert / K8SNS / K8SCluster | *(not applicable)* | Inventory/discovery only — Add not supported |

All `keyfactor_certificate_deployment` resources in this demo, including `tls_secret` and
`opaque_secret` (K8STLSSecr / K8SSecret), use full inventory-based verification: `apply`
waits for the deployed certificate to appear in the target store's inventory before
completing. Previously, `tls_secret` and `opaque_secret` required a
`skip_inventory_validation = true` workaround because the k8s-orchestrator extension's
Management (Add) job for these two store types silently failed to write the K8s Secret's
data while still reporting `Result: Success` in Command's JobHistory. That bug is fixed
upstream: https://github.com/Keyfactor/k8s-orchestrator/issues/91
