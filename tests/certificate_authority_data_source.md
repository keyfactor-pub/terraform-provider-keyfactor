# keyfactor_certificate_authority Data Source — Test Documentation

**File:** `keyfactor/data_source_keyfactor_certificate_authority_test.go`

---

## What It Tests

Read of an existing `keyfactor_certificate_authority` data source:
- Lookup by `logical_name` (string identifier)
- Lookup by numeric `id`
- Verifies `id`, `logical_name`, and `host_name` attributes

---

## Integration Test: `TestIntKeyfactorCertificateAuthorityDataSource`

Discovers the first available CA in the lab and reads it twice — once by name, once by ID.

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateAuthorityDataSource
```

---

## Unit Test: `TestUnitKeyfactorCertificateAuthorityDataSource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_authority_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_authority_data_source.params.json`

Two-step replay — lookup by `logical_name` then lookup by `id`.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateAuthorityDataSource
```
