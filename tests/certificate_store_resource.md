# keyfactor_certificate_store Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_certificate_store_test.go`

---

## What It Tests

Full CRUD lifecycle of the `keyfactor_certificate_store` resource:
- Creating a K8S TLS (`K8STLSSecr`) certificate store with kubeconfig credentials
- Reading back the store and verifying attributes
- Destroying the store at cleanup

---

## Integration Test: `TestIntKeyfactorCertificateStoreResource`

Auto-discovers an approved agent, a matching K8S store type, and creates a uniquely-named store.

```bash
KEYFACTOR_K8S_CREDENTIALS_FILE=~/path/to/k8s-creds.json make testint-run TEST_NAME=TestIntKeyfactorCertificateStoreResource
```

---

## Unit Test: `TestUnitKeyfactorCertificateStoreResource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_store_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_store_resource.params.json`

```bash
# Replay (no lab needed)
make testunit

# Record (requires K8S credentials)
KEYFACTOR_K8S_CREDENTIALS_FILE=~/path/to/k8s-creds.json make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreResource
```

---

## Notes

- K8S store types require `server_username = "kubeconfig"`, `server_password = <kubeconfig JSON>`, `server_use_ssl = true`, and a `KubeSecretType` property.
- Store path format for K8S: `<namespace>/<secret-name>` (e.g. `default/my-tls-secret`), no leading slash.
- `K8STLSSecr` uses `KubeSecretType = "tls"`, `K8SSecret` uses `KubeSecretType = "opaque"`.
