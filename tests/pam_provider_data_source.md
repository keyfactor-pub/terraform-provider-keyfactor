# keyfactor_pam_provider Data Source — Test Documentation

**File:** `keyfactor/data_source_keyfactor_pam_provider_test.go`

---

## What It Tests

Verifies the `keyfactor_pam_provider` data source can look up a provider by:
1. **Name** — provider calls `GET /PamProviders` (list) and finds by name
2. **Integer ID** — provider calls `GET /PamProviders/{id}` directly

Also verifies `provider_type_id` and `provider_type_name` are populated from the server response.

---

## Integration Test: `TestIntKeyfactorPAMProviderDataSource`

Creates an inline type + provider, then reads it back via data source by name.

| Config | What Is Validated |
|--------|-------------------|
| Minimal type + provider + data source by name | Resource `id` set; data source `id`, `name`, `provider_type_id`, `provider_type_name` all populated. |

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderDataSource
```

---

## Integration Test: `TestIntKeyfactorPAMProviderDataSourceByID`

Creates an inline type + provider, then reads it back via data source by integer ID.

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderDataSourceByID
```

---

## Unit Test: `TestUnitKeyfactorPAMProviderDataSource`

**Cassette:** `keyfactor/testdata/cassettes/pam_provider_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/pam_provider_data_source.params.json`

Two-step flow: create type + provider then look up by name, then look up by integer ID.

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Minimal type + provider + `identifier = <resource>.name` | Resource `id` set; data source `id`, `name`, `provider_type_id`, `provider_type_name` all set. |
| 2 | Same type + provider + `identifier = <resource>.id` | Data source `id`, `name`, `provider_type_id` populated via direct ID lookup. |

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-pam-provider
```

---

## VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored)
- **Params file:** Stores `type_name` and `prov_name` recorded at recording time; replay uses the same names for both steps
