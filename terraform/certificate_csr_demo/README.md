# Certificate CSR Enrollment Demo

End-to-end demonstration of `keyfactor_certificate` CSR enrollment: eight certificates
covering the minimal case, a fully configured example, and one certificate per key
algorithm (RSA-2048, RSA-4096, ECC P-256/P-384/P-521, Ed25519). Private keys are
generated locally by the `hashicorp/tls` provider. Includes import and zero-drift
verification.

> **Security note:** Private keys are stored in Terraform state. Use a remote backend
> with encryption at rest (e.g. S3 + KMS, Terraform Cloud) for any non-demo workload.

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

# Certificate enrollment targets
export TF_VAR_certificate_authority="Sub-CA"          # or "MyHost\\LogicalName" for Windows CAs
export TF_VAR_certificate_template="2YearTestWebServer"
```

> **Key algorithm support:** Ed25519 requires a CA explicitly configured for Ed25519.
> ECC key support depends on the template's allowed key algorithms.

## Files

| File | Purpose |
|---|---|
| `main.tf` | Provider config (keyfactor + tls) and outputs |
| `variables.tf` | Input variables (suffix, CA, template) |
| `keys.tf` | `tls_private_key` + `tls_cert_request` resources for each key type |
| `certificates.tf` | Eight `keyfactor_certificate` resources (CSR enrollment) |
| `_export_ids.py` | Extracts `tf_name → certificate_id` pairs from state JSON |
| `.terraformrc` | Dev override for the locally built Keyfactor provider binary |
| `GNUmakefile` | All workflow targets |

## Quickstart

```bash
# 1. Set required environment variables (see above)

# 2. Build and install the Keyfactor provider locally
make build

# 3. Initialize Terraform (also downloads hashicorp/tls from the registry)
make init

# 4. Run the full workflow
make all

# 5. Use a custom CN suffix to avoid conflicts
make all SUFFIX=_STAGING
```

## Individual targets

```
make build          Compile and install Keyfactor provider to ~/go/bin
make init           terraform init (downloads hashicorp/tls)
make validate       terraform validate
make plan           terraform plan
make apply          Generate keys + CSRs, enroll 8 certificates
make import-all     Capture state, remove certificates, re-import each by certificate ID
make drift-check    terraform plan — should show "No changes" after import
make destroy        terraform destroy -auto-approve
make clean          Remove generated files
```

## Certificate inventory

| Resource | Common name | Key algorithm |
|---|---|---|
| `minimal_csr` | `tf-demo-minimal-csr<SUFFIX>.example.com` | RSA 2048 |
| `full_csr` | `tf-demo-full-csr<SUFFIX>.example.com` | ECC P-521, SANs, metadata, renewal |
| `rsa_2048` | `tf-demo-csr-rsa2048<SUFFIX>.example.com` | RSA 2048 |
| `rsa_4096` | `tf-demo-csr-rsa4096<SUFFIX>.example.com` | RSA 4096 |
| `ecc_p256` | `tf-demo-csr-ecc256<SUFFIX>.example.com` | ECC P-256 |
| `ecc_p384` | `tf-demo-csr-ecc384<SUFFIX>.example.com` | ECC P-384 |
| `ecc_p521` | `tf-demo-csr-ecc521<SUFFIX>.example.com` | ECC P-521 |
| `ed25519` | `tf-demo-csr-ed25519<SUFFIX>.example.com` | Ed25519 |

## How it works

1. **`make apply`** first generates private keys and CSRs locally using `tls_private_key`
   and `tls_cert_request`. Each CSR is then submitted to Keyfactor Command for signing.
   The signed certificate PEM is returned; the private key never leaves the local machine
   (or Terraform state).

2. **`make import-all`** captures `terraform show -json` → `tf_state.json`, runs
   `_export_ids.py` to extract `tf_name → certificate_id` pairs for the
   `keyfactor_certificate` resources, removes them from state, and re-imports each by its
   integer certificate ID. The `tls_private_key` and `tls_cert_request` resources are
   left in state untouched.

3. **`make drift-check`** runs `terraform plan` and should report `No changes`.

4. **`make destroy`** deletes all eight certificates from Command and destroys the local
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
| Key recovery | Command re-issues on import | Key stays local; import recovers cert only |
