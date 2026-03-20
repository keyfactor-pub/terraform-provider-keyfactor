# keyfactor_certificate_store_types Data Source — Test Documentation

**File:** `keyfactor/data_source_keyfactor_certificate_store_types_test.go`

---

## What It Tests

Verifies the `keyfactor_certificate_store_types` list data source returns all available certificate store types from the lab, with correct pagination handling and attribute mapping.

---

## Integration Test: `TestIntKeyfactorCertificateStoreTypesDataSource`

Single-step test that reads all certificate store types and validates the result:

| Config | What Is Validated |
|--------|-------------------|
| `data "keyfactor_certificate_store_types"` | `store_types.#` > 0; first entry has `id`, `name`, `short_name` set. |

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateStoreTypesDataSource
```

---

## Unit Test: `TestUnitKeyfactorCertificateStoreTypesDataSource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_store_types_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_store_types_data_source.params.json`

Single-step replay that verifies pagination works (cassette covers the multi-page fetch):

| Config | What Is Validated |
|--------|-------------------|
| `data "keyfactor_certificate_store_types"` | `store_types.#` matches recorded count; entries have `id`, `name`, `short_name`. |

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreTypesDataSource
```

---

## VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored)
- **Params file:** Stores `store_type_count` to verify the correct number of types is returned on replay
