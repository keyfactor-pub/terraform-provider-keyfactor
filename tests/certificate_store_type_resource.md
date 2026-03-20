# keyfactor_certificate_store_type Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_certificate_store_type_test.go`

---

## What It Tests

Verifies full CRUD lifecycle of the `keyfactor_certificate_store_type` resource, including:
- Creating a minimal store type (no entry/job types, no custom properties)
- Updating the display name in-place (`short_name` is immutable — changes force replace)
- Importing by `short_name`
- Creating a store type with custom store properties

---

## Integration Tests

### `TestIntKeyfactorCertificateStoreTypeResource`

Three-step lifecycle against a live lab:

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Minimal config | `id` set; `name`, `short_name`, `supports_add`, `private_key_allowed`, `custom_alias_allowed` match. |
| 2 | Updated `name` (append `-v2`) | In-place update; `id` unchanged; new name reflected. |
| 3 | Import by `short_name` | Imported state matches managed state. |

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateStoreTypeResource
```

### `TestIntKeyfactorCertificateStoreTypeResourceWithProperties`

Single-step test verifying a store type with a custom property (`Host`, type `String`, required):

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateStoreTypeResourceWithProperties
```

---

## Integration Test: `TestIntKeyfactorCertificateStoreTypeDataSource`

Two-step data source test that creates a store type then reads it back:

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Resource + data source by `short_name` | Data source `id`, `name`, `short_name` match resource. |
| 2 | Data source by numeric `id` | Same attributes populated via ID lookup. |

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateStoreTypeDataSource
```

---

## Unit Test: `TestUnitKeyfactorCertificateStoreTypeResource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_store_type_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_store_type_resource.params.json`

Two-step lifecycle (create → update name):

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Minimal config | `id` set; `name`, `short_name`, `supports_add`, `supports_remove`, `private_key_allowed`, `custom_alias_allowed`, `server_required` all match. |
| 2 | Updated name (`name+"-v2"`) | `id` unchanged; updated name reflected. |

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreTypeResource
```

---

## Unit Test: `TestUnitKeyfactorCertificateStoreTypeDataSource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_store_type_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_store_type_data_source.params.json`

Two-step lookup (by `short_name`, then by numeric `id`):

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Resource + data source by `short_name` | Resource `id` set; data source `id`, `name`, `short_name`, `supports_add` match. |
| 2 | Data source by numeric `id` | `id`, `name`, `short_name` populated via ID path. |

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateStoreTypeDataSource
```

---

## VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored)
- **Params file:** Stores `name` and `short_name` recorded at recording time so replay HCL is identical
