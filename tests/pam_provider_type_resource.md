# keyfactor_pam_provider_type Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_pam_provider_type_test.go`

---

## What It Tests

Verifies the create and destroy lifecycle of the `keyfactor_pam_provider_type` resource:

- Creating a PAM provider type with two typed parameters (`Host` as string, `ApiKey` as secret)
- Verifying all computed fields (`id`, parameter `id`s, `display_name`, `data_type`, `instance_level`) are populated after create
- Import via GUID

There is no update path — all user-settable attributes have `RequiresReplace`, so any change destroys and recreates the resource.

---

## Integration Test: `TestIntKeyfactorPAMProviderTypeResource`

One-step create + import against a live lab:

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Type with `Host` (data_type=1) and `ApiKey` (data_type=2) params | `id` set; `name`, `parameters.#` = 2; both parameter `id`s set; names and data types match. |
| Import | `terraform import keyfactor_pam_provider_type.test <guid>` | All fields match post-create state. |

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderTypeResource
```

---

## Integration Test: `TestIntKeyfactorPAMProviderTypeResourceMinimal`

Creates a provider type with no parameters, then imports it.

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderTypeResourceMinimal
```

---

## Unit Test: `TestUnitKeyfactorPAMProviderTypeResource`

**Cassette:** `keyfactor/testdata/cassettes/pam_provider_type_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/pam_provider_type_resource.params.json`

Single-step create with the full two-parameter config.

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Type with `Host` and `ApiKey` parameters | `id` set; `name` matches; `parameters.#` = 2; names, `data_type`, and computed `id`s all correct. |

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
- **Params file:** Stores `type_name` recorded at recording time; replay uses the same name to construct identical HCL
