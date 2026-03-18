# keyfactor_pam_provider_type Data Source — Test Documentation

**File:** `keyfactor/data_source_keyfactor_pam_provider_type_test.go`

---

## What It Tests

Verifies the `keyfactor_pam_provider_type` data source can look up a provider type by:
1. **Name** — provider calls `GET /PamProviders/Types` (list) and finds by name
2. **GUID** — provider calls `GET /PamProviders/Types` (list) and finds by GUID

Also verifies all nested `parameters` fields (`id`, `name`, `display_name`, `data_type`, `instance_level`) are correctly populated.

---

## Integration Test: `TestIntKeyfactorPAMProviderTypeDataSource`

Creates an inline provider type, then reads it back via data source by name.

| Config | What Is Validated |
|--------|-------------------|
| Type resource + data source by name | Resource `id` set; data source `id`, `name`, `parameters.#` = 2 all populated. |

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderTypeDataSource
```

---

## Integration Test: `TestIntKeyfactorPAMProviderTypeDataSourceByGUID`

Creates an inline provider type, then reads it back via data source by GUID.

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderTypeDataSourceByGUID
```

---

## Unit Test: `TestUnitKeyfactorPAMProviderTypeDataSource`

**Cassette:** `keyfactor/testdata/cassettes/pam_provider_type_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/pam_provider_type_data_source.params.json`

Two-step flow: create type + lookup by name, then lookup by GUID.

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Type resource + `identifier = <resource>.name` | Resource `id` set; data source `id`, `name`, `parameters.#` = 2, parameter names match. |
| 2 | Type resource + `identifier = <resource>.id` | Data source `id`, `name`, `parameters.#` = 2 populated via GUID lookup path. |

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-pam-provider-type
```

---

## VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored)
- **Params file:** Stores `type_name` recorded at recording time; replay uses the same name for both steps
