# keyfactor_pam_provider Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_pam_provider_test.go`

---

## What It Tests

Verifies the full create/update/delete lifecycle of the `keyfactor_pam_provider` resource, including:

- Creating a PAM provider backed by an inline `keyfactor_pam_provider_type` with two parameters (`Host` and `ApiKey`)
- Providing typed `param_values` for both parameters
- Updating the provider name and parameter values in-place
- Import via integer ID, confirming `param_values` are excluded from import verify (write-only — the server stores them as GUID references and never returns plaintext)

Also covers the `TestIntKeyfactorPAMProviderResourceMinimal` variant: a provider created without any `param_values`.

---

## Integration Test: `TestIntKeyfactorPAMProviderResource`

Two-step lifecycle + import against a live lab:

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Type + provider with `Host` and `ApiKey` params | `id` set; `name`, `provider_type_id`, `param_values.#` = 2. |
| 2 | Updated name + new param values | `id` unchanged; `name` updated; `param_values.#` = 2. |
| Import | `terraform import keyfactor_pam_provider.test <id>` | Metadata fields match; `param_values` excluded from verify (write-only). |

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderResource
```

---

## Integration Test: `TestIntKeyfactorPAMProviderResourceMinimal`

Single-step create of a provider with no `param_values`, then import.

```bash
make testint-run TEST_NAME=TestIntKeyfactorPAMProviderResourceMinimal
```

---

## Unit Test: `TestUnitKeyfactorPAMProviderResource`

**Cassette:** `keyfactor/testdata/cassettes/pam_provider_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/pam_provider_resource.params.json`

Two-step flow: create type + provider → update name and param values.

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Type + provider (`Host = "https://pam.example.com"`, `ApiKey = "secret123"`) | `id` set; `name`, `provider_type_id`, `param_values.#` = 2. |
| 2 | Same type + provider with updated name and param values | `id` unchanged; `name` = `<original>-updated`; `param_values.#` = 2. |

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
- **Params file:** Stores `type_name` and `prov_name` recorded at recording time; replay uses the same names to construct identical HCL
- **Note:** PAM `param_values` are preserved from plan in state — the server never returns plaintext secret values
