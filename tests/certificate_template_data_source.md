# keyfactor_certificate_template Data Source — Test Documentation

**Files:**
- `keyfactor/data_source_keyfactor_certificate_template_test.go` (new framework)
- `keyfactor/data_source_keyfactor_template_test.go` (legacy SDK-based wrapper)

---

## What It Tests

Read of an existing `keyfactor_certificate_template` data source via the `identifier` field
(accepts template name or numeric ID):
- Lookup by `common_name` (string)
- Lookup by numeric `id`
- Verifies `id`, `common_name`, and `template_name` attributes

---

## Integration Tests

| Test | Description |
|------|-------------|
| `TestIntKeyfactorCertificateTemplateDataSource` | Discovers a template and reads it by name then by ID |
| `TestIntKeyfactorCertificateTemplateDataSourceLegacy` | Legacy test using the original `TestAcc`-style harness |

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateTemplateDataSource
```

---

## Unit Tests

| Test | Cassette |
|------|---------|
| `TestUnitKeyfactorCertificateTemplateDataSource` | `certificate_template_data_source` |
| `TestUnitKeyfactorCertificateTemplateDataSourceLegacy` | `certificate_template_data_source` (shared) |

Both unit tests share the same cassette.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateTemplateDataSource
```
