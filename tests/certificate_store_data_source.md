# keyfactor_certificate_store Data Source — Test Documentation

**File:** `keyfactor/data_source_keyfactor_certificate_store_test.go`

---

## What It Tests

Read of an existing `keyfactor_certificate_store` data source via two lookup modes:
1. **By `client_machine` + `store_path`** — the original lookup mode
2. **By `id` (GUID)** — new; the store is looked up directly via `GET /CertificateStores/{guid}`

---

## Integration Test: `TestIntKeyfactorCertificateStoreDataSource`

Creates a K8S TLS store, then reads it back by `client_machine` + `store_path`.

```bash
KEYFACTOR_K8S_CREDENTIALS_FILE=~/path/to/k8s-creds.json make testint-run TEST_NAME=TestIntKeyfactorCertificateStoreDataSource
```

---

## Unit Tests

| Test | Cassette | Lookup Mode |
|------|---------|-------------|
| `TestUnitKeyfactorCertificateStoreDataSource` | `certificate_store_data_source` | `client_machine` + `store_path` |
| `TestUnitKeyfactorCertificateStoreDataSourceByGUID` | `certificate_store_data_source_by_guid` | `id` (GUID) |

```bash
# Replay (no lab needed)
make testunit

# Record cassettes
KEYFACTOR_K8S_CREDENTIALS_FILE=~/path/to/k8s-creds.json make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreDataSource
KEYFACTOR_K8S_CREDENTIALS_FILE=~/path/to/k8s-creds.json make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreDataSourceByGUID
```

---

## Notes

- `id` is now `Optional+Computed` — it accepts GUID input for direct lookup, or is populated from the response.
- `client_machine` and `store_path` are now `Optional+Computed` — they are populated from the server response even when looking up by GUID.
- A validation error is returned if neither `id` nor both `client_machine`+`store_path` are provided.
