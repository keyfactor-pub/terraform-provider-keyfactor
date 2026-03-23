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

# Certificate enrollment targets
export TF_VAR_certificate_authority="Sub-CA"          # or "MyHost\\LogicalName" for Windows CAs
export TF_VAR_certificate_template="2YearTestWebServer"
```

> **Note:** If `KEYFACTOR_USERNAME` / `KEYFACTOR_PASSWORD` are also set, the provider
> prefers basic auth over OAuth. Unset them if you want OAuth.

> **Key algorithm support:** Not all CAs or templates support every key type. The Ed25519
> example requires a CA explicitly configured for Ed25519. ECC key support depends on the
> template's allowed key algorithms. Enrollments for unsupported key types will fail with
> a CA error.

## Files

| File | Purpose |
|---|---|
| `versions.tf` | `terraform` block and `required_providers` |
| `providers.tf` | Provider configurations |
| `variables.tf` | Input variables (suffix, CA, template, key_password) |
| `certificates.tf` | Eleven `keyfactor_certificate` resources |
| `outputs.tf` | Output values (thumbprints, key types, IDs, PEMs, private keys) |
| `_export_ids.py` | Extracts `tf_name → certificate_id` pairs from state JSON |
| `.terraformrc` | Dev override pointing Terraform at the locally built provider binary |
| `GNUmakefile` | All workflow targets |

## Quickstart

```bash
# 1. Set required environment variables (see above)

# 2. Build and install the provider locally
make build

# 3. Initialize Terraform
make init

# 4. Run the full workflow
make all

# 5. Use a custom CN suffix to avoid conflicts
make all SUFFIX=_STAGING
```

## Individual targets

```
make build          Compile and install provider to ~/go/bin
make init           terraform init
make validate       terraform validate
make plan           terraform plan
make apply          terraform apply -auto-approve (enrolls 11 certificates)
make import-all     Capture state, remove resources, re-import each by certificate ID
make drift-check    terraform plan — should show "No changes" after import
make destroy        terraform destroy -auto-approve
make clean          Remove generated files
```

## Certificate inventory

| Resource | Common name | Key |
|---|---|---|
| `minimal_pfx` | `tf-demo-minimal-pfx<SUFFIX>.example.com` | CA/template default |
| `full_pfx` | `tf-demo-full-pfx<SUFFIX>.example.com` | ECC P-521, SANs, metadata, renewal |
| `rsa_2048` | `tf-demo-rsa2048<SUFFIX>.example.com` | RSA 2048-bit |
| `rsa_3072` | `tf-demo-rsa3072<SUFFIX>.example.com` | RSA 3072-bit |
| `rsa_4096` | `tf-demo-rsa4096<SUFFIX>.example.com` | RSA 4096-bit |
| `rsa_8192` | `tf-demo-rsa8192<SUFFIX>.example.com` | RSA 8192-bit |
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

4. **`make destroy`** deletes all eight certificates from the Command instance.

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
  certificate_enrollment_pattern = "Default Pattern"
  key_password                   = var.key_password
}
```
