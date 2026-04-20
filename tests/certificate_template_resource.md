# keyfactor_certificate_template Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_certificate_template_test.go`

> **Note:** Certificate templates cannot be created via the API — they are imported from the CA.
> Create intentionally returns an error; the resource is managed via import only.

---

## What It Tests

Import and read of an existing `keyfactor_certificate_template` resource:
- Importing a template by numeric ID
- Verifying `id`, `common_name`, and `template_name` attributes after import

---

## Integration Test: `TestIntKeyfactorCertificateTemplateResourceImport`

Discovers the first available template in the lab and imports it by ID.

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateTemplateResourceImport
```

---

## Unit Test: `TestUnitKeyfactorCertificateTemplateResource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_template_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_template_resource.params.json`

Replays the import of a template by ID.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateTemplateResource
```

---

## Notes

- `CheckDestroy` is `nil` — delete is a no-op (templates cannot be deleted via API).
- Update is tested separately via `TestIntKeyfactorCertificateTemplateResourceUpdateDirect` (direct API call, not framework-driven).
