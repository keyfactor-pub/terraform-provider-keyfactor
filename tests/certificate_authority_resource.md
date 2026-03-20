# keyfactor_certificate_authority Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_certificate_authority_test.go`

> **Note:** Certificate authorities cannot be created via the API — the Command server validates
> CA connectivity during creation. These tests import an existing CA and exercise read operations.

---

## What It Tests

Import and read of an existing `keyfactor_certificate_authority` resource:
- Importing a CA by numeric ID
- Verifying `id`, `logical_name`, and `host_name` attributes after import

---

## Integration Test: `TestIntKeyfactorCertificateAuthorityResourceImport`

Discovers the first available CA in the lab and imports it by ID.

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateAuthorityResourceImport
```

---

## Unit Test: `TestUnitKeyfactorCertificateAuthorityResource`

**Cassette:** `keyfactor/testdata/cassettes/certificate_authority_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_authority_resource.params.json`

Replays the import of a CA by ID via the `GET /CertificateAuthority/{id}` endpoint.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateAuthorityResource
```

---

## Notes

- `CheckDestroy` is set to `nil` — the test framework does not attempt to delete the CA (it is not owned by the test).
- Secret fields (`explicit_password`, `auth_certificate_password`, `client_secret`) are write-only and preserved from plan/state during Read.
