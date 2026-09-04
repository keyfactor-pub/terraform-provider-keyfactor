# release_validation_demo

Trimmed release-gate smoke test: one apply exercises agent lookup, PFX + CSR
certificate enrollment, 6 K8S certificate store types, and 4 certificate
deployments.

## What it covers

- `data.keyfactor_agent`
- `keyfactor_certificate` (1 PFX, 1 CSR via the `hashicorp/tls` provider)
- `keyfactor_certificate_store`: K8STLSSecr, K8SSecret, K8SJKS, K8SPKCS12, K8SNS, K8SCluster
- `keyfactor_certificate_deployment` (tls_secret, opaque_secret, jks, pkcs12)

Deliberately narrower than `k8s_orchestrator_demo` (no K8SCert, no
buddy-password JKS/PKCS12 variants); this demo is a fast pass across common
surfaces, not a deep per-feature test.

## Variables

See `variables.tf`. Defaults target the kfclab lab: `certificate_authority =
"OpenBao PKI"`, `certificate_enrollment_pattern = "Lab - AnyCA (lab-role)"`,
`agent_identifier = "kfclab-uo-secondary-uo"`.

kfclab's K8S orchestrators use in-cluster pod-identity auth by default (no
kubeconfig needed). Set `k8s_server_password_file` only for orchestrators
without that RBAC binding.

## Running

```sh
make build
make init
make lifecycle
```
