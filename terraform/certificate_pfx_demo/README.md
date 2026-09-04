# Certificate PFX Enrollment Demo

End-to-end demonstration of `keyfactor_certificate` PFX enrollment: eleven certificates
covering the minimal case, a fully configured example, and one certificate per supported
key algorithm (RSA-2048/3072/4096/8192, ECC P-256/P-384/P-521, Ed25519, Ed448). Includes
import and zero-drift verification.

## Prerequisites

| Requirement | Details |
|---|---|
| Go ≥ 1.21 | Required to build the provider |
| Terraform ≥ 1.3 | CLI must be on `$PATH` |
| Python 3 | Used by `_export_ids.py` |
| Keyfactor Command ≥ v11.7 | OAuth credentials required |

### Environment variables

```bash
# Keyfactor auth
export KEYFACTOR_HOSTNAME=your-command-host.example.com
export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token

# Optional — skip TLS verification for self-signed certs
export KEYFACTOR_SKIP_VERIFY=true

# Optional — extend HTTP timeout for slow servers (RSA-8192 needs ~5 min)
export KEYFACTOR_CLIENT_TIMEOUT=600   # seconds; default is 60

# Certificate enrollment targets
export TF_VAR_certificate_authority="OpenBao PKI"          # or "MyHost\\LogicalName" for Windows CAs
export TF_VAR_certificate_template="AnyCA_lab-role"
```

> **Note:** If `KEYFACTOR_USERNAME` / `KEYFACTOR_PASSWORD` are also set, the provider
> prefers basic auth over OAuth. Unset them if you want OAuth.

> **Key algorithm support:** Not all CAs or templates support every key type. Ed25519 and
> Ed448 require a CA explicitly configured for those algorithms. ECC key support depends
> on the template's allowed key algorithms.

> **⚠ RSA-8192 timeout:** Server-side RSA-8192 key generation can take 4-5 minutes.
> Set `KEYFACTOR_CLIENT_TIMEOUT=600` (seconds) before running `make apply` to extend
> the HTTP client timeout to 10 minutes. Without this the default 60-second timeout
> will cause `rsa_8192` to fail.

> **⚠ RSA-8192 intermittent `ContentLength` failure:** Separately from the timeout
> above, the initial `rsa_8192` enrollment attempt has been observed to fail with
> `http: ContentLength=160 with Body length 0` even with `KEYFACTOR_CLIENT_TIMEOUT`
> raised (reproduced identically on two attempts, 2026-08-17). Command completes the
> enrollment server-side despite the client-side failure — confirmed via direct API
> query against the lab, with orphaned certificate IDs 364, 367, and 369 observed and
> left in place as acceptable lab noise, not cleaned up. A retry (e.g. re-running
> `make lab-update` or `make apply` again) succeeds. This is a known lab/environment
> issue, not a code bug, and is not currently investigated further here. Note: this
> symptom is superficially similar to the client-side-timeout shape that the
> orphaned-PFX-recovery feature (`isTimeoutShapedError` in `keyfactor/helpers.go`)
> already detects and recovers from, but a `ContentLength` mismatch does not match any
> of that function's checks, so this case is NOT currently auto-recovered — a possible
> gap for future investigation, not addressed here.

## Files

| File | Purpose |
|---|---|
| `versions.tf` | `terraform` block and `required_providers` |
| `providers.tf` | Provider configurations |
| `variables.tf` | Input variables (suffix, CA, template, key_password, metadata, renew_days) |
| `certificates.tf` | Eleven `keyfactor_certificate` resources |
| `outputs.tf` | Output values (thumbprints, key types, IDs, PEMs, private keys) |
| `_export_ids.py` | Extracts `tf_name → certificate_id` pairs from state JSON |
| `.terraformrc` | Dev override pointing Terraform at the locally built provider binary |
| `GNUmakefile` | All workflow targets |

## Quickstart

```bash
# 1. Build and install the provider locally
make build

# 2. Initialize Terraform
make init

# 3a. Full lifecycle using lab credentials from ~/.env_kfclab (recommended)
#     Default suffix: _PFX_DEMO
make lifecycle

# 3b. Or set env vars manually and run individual steps
export KEYFACTOR_HOSTNAME=... # see Environment variables above
make apply
make lab-update        # modify metadata / renew_days — should show in-place change only
make plan              # verify no drift
make import-all
make apply             # reconcile — writes write-only params (key_password, etc.) into state
make drift-check       # should show "No changes"
make destroy

# 3c. Use a custom CN suffix to avoid conflicts with other runs
make lifecycle SUFFIX=_STAGING
```

## Individual targets

```
make build          Compile and install provider to ~/go/bin
make init           terraform init
make validate       terraform validate
make plan           terraform plan
make apply          terraform apply -auto-approve (enrolls 11 certificates)
make import-all     Capture state, remove resources, re-import each by certificate ID
make drift-check    terraform plan — only write-only fields (key_password) may appear after import
make destroy        terraform destroy -auto-approve
make clean          Remove generated files
```

### Lab convenience targets

These targets source `KEYFACTOR_ENV_FILE` (default: `~/.env_kfclab`) automatically and set
`TF_VAR_certificate_authority`, `TF_VAR_certificate_enrollment_pattern`, and
`KEYFACTOR_CLIENT_TIMEOUT` before delegating to the base target.

```
make lifecycle        Full test: apply → update → plan → import-all → apply (reconcile) → drift-check → destroy
make lab-plan         Plan using lab credentials
make lab-apply        Apply using lab credentials
make lab-update       Apply with updated metadata/renew_days — verifies in-place update path
make lab-import-all   Import all certificates using lab credentials
make lab-drift-check  Drift-check using lab credentials
make lab-destroy      Destroy using lab credentials
```

Override any lab setting on the command line:

```bash
make KEYFACTOR_ENV_FILE=~/.env_prod LAB_CA="PROD-OpenBao-PKI" LAB_PATTERN="" lifecycle
```

## Certificate inventory

| Resource | Common name | Key |
|---|---|---|
| `minimal_pfx` | `tf-demo-minimal-pfx<SUFFIX>.example.com` | CA/template default |
| `full_pfx` | `tf-demo-full-pfx<SUFFIX>.example.com` | ECC P-521, SANs, metadata, renewal |
| `rsa_2048` | `tf-demo-rsa2048<SUFFIX>.example.com` | RSA 2048-bit |
| `rsa_3072` | `tf-demo-rsa3072<SUFFIX>.example.com` | RSA 3072-bit |
| `rsa_4096` | `tf-demo-rsa4096<SUFFIX>.example.com` | RSA 4096-bit |
| `rsa_8192` | `tf-demo-rsa8192<SUFFIX>.example.com` | RSA 8192-bit ⚠ |
| `ecc_p256` | `tf-demo-ecc256<SUFFIX>.example.com` | ECC P-256 |
| `ecc_p384` | `tf-demo-ecc384<SUFFIX>.example.com` | ECC P-384 |
| `ecc_p521` | `tf-demo-ecc521<SUFFIX>.example.com` | ECC P-521 |
| `ed25519` | `tf-demo-ed25519<SUFFIX>.example.com` | Ed25519 |
| `ed448` | `tf-demo-ed448<SUFFIX>.example.com` | Ed448 |

## How it works

1. **`make apply`** enrolls eleven certificates. For each, Keyfactor Command generates the
   key pair (PFX enrollment), signs the certificate, and returns the signed cert and
   private key (if the template has KeyRetention enabled).

2. **`make import-all`** captures `terraform show -json` → `tf_state.json`, runs
   `_export_ids.py` to extract `tf_name → certificate_id` pairs, removes every managed
   resource from state, then re-imports each by its integer certificate ID.

3. **`make drift-check`** runs `terraform plan` and should report `No changes`, proving
   the imported state matches the configuration.

4. **`make destroy`** deletes all eleven certificates from the Command instance.

## Import identifier

Certificates are imported by their **integer certificate ID**:

```bash
terraform import keyfactor_certificate.rsa_2048 1042
```

## Using enrollment patterns (Command v25+)

Replace `certificate_template` with `certificate_enrollment_pattern` in `certificates.tf`:

```hcl
resource "keyfactor_certificate" "minimal_pfx" {
  common_name                    = "tf-demo-minimal-pfx${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_enrollment_pattern = "Lab - AnyCA (lab-role)"
  key_password                   = var.key_password
}
```
