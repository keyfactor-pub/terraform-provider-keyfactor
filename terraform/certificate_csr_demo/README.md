# Certificate CSR Enrollment Demo

End-to-end demonstration of `keyfactor_certificate` CSR enrollment: eleven certificates
covering the minimal case, a fully configured example, and one certificate per key
algorithm (RSA-2048/3072/4096/8192, ECC P-256/P-384/P-521, Ed25519, Ed448). Private keys
are generated locally — RSA and ECC via `hashicorp/tls`, Ed448 via OpenSSL through the
`hashicorp/external` data source. Includes import and zero-drift verification.

> **Security note:** Private keys are stored in Terraform state. Use a remote backend
> with encryption at rest (e.g. S3 + KMS, Terraform Cloud) for any non-demo workload.

## Prerequisites

| Requirement | Details |
|---|---|
| Go ≥ 1.21 | Required to build the provider |
| Terraform ≥ 1.3 | CLI must be on `$PATH` |
| Python 3 | Used by `_export_ids.py` and `gen_ed448_csr.sh` |
| OpenSSL ≥ 1.1.1 | Required for Ed448 key/CSR generation |
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

# Certificate enrollment targets
export TF_VAR_certificate_authority="Sub-CA"          # or "MyHost\\LogicalName" for Windows CAs
export TF_VAR_certificate_template="2YearTestWebServer"
```

> **Key algorithm support:** Ed25519 and Ed448 require a CA explicitly configured for those
> algorithms. ECC key support depends on the template's allowed key algorithms.

> **Ed448 stale key conflict:** `gen_ed448_csr.sh` reuses the private key from
> `.ed448_key.pem` across runs to produce a deterministic CSR. If an old cert with the
> same subject and key is still active on the server, enrollment will fail with a conflict
> error. Delete `.ed448_key.pem` before running `make apply` to force a new key.

## Files

| File | Purpose |
|---|---|
| `versions.tf` | `terraform` block and `required_providers` |
| `providers.tf` | Provider configurations (keyfactor, tls, external) |
| `variables.tf` | Input variables (suffix, CA, template, metadata, renew_days) |
| `keys.tf` | `tls_private_key`, `tls_cert_request`, and Ed448 `external` data source |
| `certificates.tf` | Eleven `keyfactor_certificate` resources (CSR enrollment) |
| `outputs.tf` | Output values (thumbprints, key types, IDs, PEMs, private keys) |
| `gen_ed448_csr.sh` | OpenSSL wrapper that generates a stable Ed448 key + CSR |
| `_export_ids.py` | Extracts `tf_name → certificate_id` pairs from state JSON |
| `.terraformrc` | Dev override for the locally built Keyfactor provider binary |
| `GNUmakefile` | All workflow targets |

## Quickstart

```bash
# 1. Build and install the Keyfactor provider locally
make build

# 2. Initialize Terraform (also downloads hashicorp/tls from the registry)
make init

# 3a. Full lifecycle using lab credentials from ~/.env_ses2541 (recommended)
#     Default suffix: _CSR_DEMO
make lifecycle

# 3b. Or set env vars manually and run individual steps
export KEYFACTOR_HOSTNAME=... # see Environment variables above
make apply
make lab-update    # modify metadata/renew_days; also tests full→minimal (omit block = clear from server)
make import-all
make apply         # reconcile — writes write-only params (enrollment_pattern, CSR) into state
make drift-check   # should show "No changes"
make destroy

# 3c. Use a custom CN suffix to avoid conflicts with other runs
make lifecycle SUFFIX=_STAGING
```

## Individual targets

```
make build          Compile and install Keyfactor provider to ~/go/bin
make init           terraform init (downloads hashicorp/tls)
make validate       terraform validate
make plan           terraform plan
make apply          Generate keys + CSRs, enroll 11 certificates
make import-all     Capture state, remove certificates, re-import each by certificate ID
make drift-check    terraform plan — should show "No changes" after import
make destroy        terraform destroy -auto-approve
make clean          Remove generated files
```

### Lab convenience targets

These targets source `LAB_ENV_FILE` (default: `~/.env_ses2541`) automatically and set
`TF_VAR_certificate_authority`, `TF_VAR_certificate_enrollment_pattern`, and
`KEYFACTOR_CLIENT_TIMEOUT` before delegating to the base target.

```
make lifecycle        Full test: apply → update (apply+plan+minimal+plan) → import-all → apply (reconcile) → drift-check → destroy
make lab-plan         Plan using lab credentials
make lab-apply        Apply using lab credentials
make lab-update       Apply with updated metadata/renew_days + full→minimal; verifies in-place update
make lab-import-all   Import all certificates using lab credentials
make lab-drift-check  Drift-check using lab credentials
make lab-destroy      Destroy using lab credentials
```

Override any lab setting on the command line:

```bash
make LAB_ENV_FILE=~/.env_prod LAB_CA="PROD-Sub-CA" LAB_PATTERN="" lifecycle
```

## Certificate inventory

| Resource | Common name | Key algorithm |
|---|---|---|
| `minimal_csr` | `tf-demo-minimal-csr<SUFFIX>.example.com` | RSA 2048 |
| `full_csr` | `tf-demo-full-csr<SUFFIX>.example.com` | ECC P-521, SANs, metadata, renewal |
| `rsa_2048` | `tf-demo-csr-rsa2048<SUFFIX>.example.com` | RSA 2048 |
| `rsa_3072` | `tf-demo-csr-rsa3072<SUFFIX>.example.com` | RSA 3072 |
| `rsa_4096` | `tf-demo-csr-rsa4096<SUFFIX>.example.com` | RSA 4096 |
| `rsa_8192` | `tf-demo-csr-rsa8192<SUFFIX>.example.com` | RSA 8192 |
| `ecc_p256` | `tf-demo-csr-ecc256<SUFFIX>.example.com` | ECC P-256 |
| `ecc_p384` | `tf-demo-csr-ecc384<SUFFIX>.example.com` | ECC P-384 |
| `ecc_p521` | `tf-demo-csr-ecc521<SUFFIX>.example.com` | ECC P-521 |
| `ed25519` | `tf-demo-csr-ed25519<SUFFIX>.example.com` | Ed25519 |
| `ed448` | `tf-demo-csr-ed448<SUFFIX>.example.com` | Ed448 (OpenSSL via external) |

## How it works

1. **`make apply`** first generates private keys and CSRs locally. RSA and ECC keys use
   `tls_private_key` and `tls_cert_request`; the Ed448 key/CSR is generated by
   `gen_ed448_csr.sh` via the `external` data source (OpenSSL required). Each CSR is
   then submitted to Keyfactor Command for signing. The signed certificate PEM is
   returned; the private key never leaves the local machine (or Terraform state).

2. **`make import-all`** captures `terraform show -json` → `tf_state.json`, runs
   `_export_ids.py` to extract `tf_name → certificate_id` pairs for the
   `keyfactor_certificate` resources, removes them from state, and re-imports each by its
   integer certificate ID. The `tls_private_key` and `tls_cert_request` resources are
   left in state untouched.

3. **`make drift-check`** runs `terraform plan` and should report `No changes`.

4. **`make destroy`** deletes all eleven certificates from Command and destroys the local
   key material from state.

## Import identifier

Certificates are imported by their **integer certificate ID**:

```bash
terraform import keyfactor_certificate.rsa_2048 1042
```

## Key differences from PFX enrollment

| | PFX enrollment | CSR enrollment |
|---|---|---|
| Key generation | Keyfactor Command (server-side) | Local (`hashicorp/tls`) |
| Private key in state | Yes (via `private_key` attribute) | Yes (via `tls_private_key`) |
| `key_password` required | Yes | No |
| `key_type` / `key_size` / `curve` | Set in HCL | Embedded in CSR — **cannot** be set in HCL |
| Key recovery on import | Attempted via Command key archival API during `import`; run reconcile `apply` with `key_password` to populate `private_key` in state | Key stays local; import recovers cert only |
