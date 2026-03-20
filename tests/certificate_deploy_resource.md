# keyfactor_certificate_deployment Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_certificate_deploy_test.go`

---

## What It Tests

Full deployment of a certificate to a certificate store:
- Enrolling a certificate (via enrollment pattern or template)
- Creating a K8S TLS certificate store
- Deploying the certificate to the store via `keyfactor_certificate_deployment`
- Verifying `id`, `certificate_id`, and `certificate_store_id` are set

---

## Prerequisites

Deployment to a K8S TLS store (`K8STLSSecr`) requires:
1. **Key retention** enabled on the certificate template — the server must store the private key for later retrieval. Set `KeyRetention` to `"EndEntityCertificate"` or similar on the template in Keyfactor Command.
2. **K8S credentials** — set `KEYFACTOR_K8S_CREDENTIALS_FILE` (path to kubeconfig JSON) or `KEYFACTOR_K8S_SERVER_PASSWORD` (kubeconfig JSON content).

---

## Integration Test: `TestIntKeyfactorCertificateDeployResource`

Auto-discovers a CA, agent, store type, and enrollment pattern (or template), then deploys.

```bash
KEYFACTOR_K8S_CREDENTIALS_FILE=~/path/to/k8s-creds.json make testint-run TEST_NAME=TestIntKeyfactorCertificateDeployResource
```

---

## Unit Test: `TestUnitKeyfactorCertificateDeployResource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_deploy_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_deploy_resource.params.json`

Full apply: cert enrollment → store creation → deployment. Single-step with three resource checks.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette (requires K8S credentials + template with key retention enabled)
KEYFACTOR_K8S_CREDENTIALS_FILE=~/path/to/k8s-creds.json make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateDeployResource
```

---

## Notes

- If K8S credentials are not set, the recording path skips with a clear message.
- The test uses enrollment patterns (v25+) when available; falls back to template-based enrollment.
- `K8STLSSecr` store type is preferred for the test (cert + private key in a TLS secret).
