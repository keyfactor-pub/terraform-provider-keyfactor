# keyfactor_application Data Source — Test Documentation

**File:** `keyfactor/data_source_keyfactor_application_test.go`

> **Note:** On Keyfactor Command v25.0+ this data source uses the `/Applications` endpoint.
> On pre-v25 Command it transparently falls back to `/CertificateStoreContainers`.
> The `x-keyfactor-product-version` response header is read during authentication to detect
> the server version automatically.

---

## What It Tests

Verifies the `keyfactor_application` data source can look up an application by:
1. **Name** — provider calls `ListApplications()` then `GetApplication(id)`
2. **Integer ID** — provider calls `GetApplication(id)` directly

Also verifies the `certificate_store_ids` list is correctly populated (empty list for a new application with no stores).

---

## Integration Test: `TestIntKeyfactorApplicationDataSource`

One-step test: creates an application resource and reads it back via the data source by name in the same Terraform config.

| Config | What Is Validated |
|--------|-------------------|
| Resource + data source by name | Resource `id` set; data source `id`, `name`, `certificate_store_ids.#` all populated. |

```bash
make testint-run TEST_NAME=TestIntKeyfactorApplicationDataSource
```

---

## Unit Test: `TestUnitKeyfactorApplicationDataSource`

**Cassette:** `keyfactor/testdata/cassettes/application_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/application_data_source.params.json`

Two-step flow: create + lookup by name, then lookup by integer ID.

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Resource + `identifier = <resource>.name` | Resource `id` set; data source `id`, `name`, `overwrite_schedules`, `certificate_store_ids.#` all populated. |
| 2 | Resource + `identifier = <resource>.id` | Data source `id`, `name`, `certificate_store_ids.#` populated via numeric ID lookup path. |

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-application
```

---

## VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored)
- **Params file:** Stores `app_name` recorded at recording time; replay uses the same name for both steps
