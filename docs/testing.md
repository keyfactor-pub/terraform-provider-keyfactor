# Testing Documentation

This document describes the test suite for the Keyfactor Terraform provider. Each section covers a specific test, what it validates, how to run it, and any prerequisites.

For general test infrastructure details (VCR cassettes, discovery helpers, env vars), see [CLAUDE.md](../CLAUDE.md).

---

## Table of Contents

- [Certificate Resource: Format Change (Integration)](#testintkeyfactorcertificateresource_formatchange)
- [Certificate Resource: Format Change (Unit/VCR)](#testunitkeyfactorcertificateresource_formatchange)

---

## TestIntKeyfactorCertificateResource_FormatChange

**File:** `keyfactor/resource_keyfactor_certificate_test.go`
**Tier:** Integration (`TestInt*`)
**Fixes:** [#150 — BUG: Changing certificate_format forces recreation](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/150)

### What It Tests

Verifies that changing the `certificate_format` attribute on a `keyfactor_certificate` resource triggers an **in-place update** rather than forcing resource destruction and recreation.

Prior to the fix, `certificate_format` had a `RequiresReplace()` plan modifier, which meant any change (e.g., adding `certificate_format = "PEM"` to an existing resource) would destroy the certificate and re-enroll a new one. This was incorrect because `certificate_format` only controls the download/output format — the certificate itself doesn't change.

### Test Steps

| Step | Config Change | What Is Validated |
|------|--------------|-------------------|
| 1 | Create with **no** `certificate_format` (default) | Certificate is created. `serial_number`, `thumbprint`, `certificate_pem`, and `certificate_chain` are populated. Binary format fields (`pfx`, `jks`, `zip`) are absent. The `id` is captured for comparison in later steps. |
| 2 | Add `certificate_format = "PEM"` | The `id` is **unchanged** (no recreation). PEM fields populated, binary fields absent. |
| 3 | Switch to `certificate_format = "PFX"` | The `id` is **unchanged**. `pfx` is populated, PEM and other binary fields are absent. |
| 4 | Switch to `certificate_format = "JKS"` | The `id` is **unchanged**. `jks` is populated, all other format fields are absent. |
| 5 | Switch to `certificate_format = "ZIP"` | The `id` is **unchanged**. `zip` is populated, all other format fields are absent. |
| 6 | Switch back to `certificate_format = "PEM"` | The `id` is **unchanged**. PEM fields populated again, binary fields absent. Full round-trip validated. |

### Key Assertions

- **No recreation:** The `id` attribute is compared across all six steps via `checkFormatFields()`. If it changes, the test fails with an explicit error message indicating the certificate was recreated.
- **Correct field population:** Each format step validates that ONLY the expected format's fields are populated:
  - **PEM** (or default): `certificate_pem` and `certificate_chain` are set; `pfx`, `jks`, `zip` are absent.
  - **PFX**: `pfx` is set; PEM fields and `jks`, `zip` are absent.
  - **JKS**: `jks` is set; PEM fields and `pfx`, `zip` are absent.
  - **ZIP**: `zip` is set; PEM fields and `pfx`, `jks` are absent.
- **Effective format normalization:** Switching between no format (empty/default) and `"PEM"` does not trigger a re-download because both resolve to the same effective format internally via `effectiveCertificateFormat()`.

### How to Run

```bash
# Requires lab connection credentials in env file
make testint-run TEST_NAME=TestIntKeyfactorCertificateResource_FormatChange
```

### Prerequisites

- Lab connection env vars (`KEYFACTOR_HOSTNAME`, OAuth credentials)
- At least one certificate authority available in the lab
- Either an enrollment pattern (Command v25+) or a certificate template
- **For binary format steps (PFX/JKS/ZIP):** The CA must support private key recovery (key retention/archival enabled). If the CA does not store private keys (e.g., some EJBCA configurations), binary format recovery will fail with "No private key could be found for the given certificate."

### Helper Functions

- `checkFormatFields(format, originalID)` — validates correct fields for the given format and checks `id` stability
- `certFormatConfig(enrollmentPattern, templateName, ca, cn, format)` — generates HCL config using either enrollment pattern or template
- `testAccCertPFXConfigWithFormat(templateName, ca, cn, format)` — template-based enrollment with optional `certificate_format`
- `testAccCertPFXConfigEnrollmentPatternWithFormat(enrollmentPattern, ca, cn, format)` — enrollment-pattern-based with optional `certificate_format`

Both HCL generators accept an empty string for `format` to omit the `certificate_format` attribute entirely.

---

## TestUnitKeyfactorCertificateResource_FormatChange

**File:** `keyfactor/resource_keyfactor_certificate_test.go`
**Tier:** Unit (`TestUnit*`)
**Cassette:** `keyfactor/testdata/cassettes/certificate_resource_format_change.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_resource_format_change.params.json`
**Fixes:** [#150 — BUG: Changing certificate_format forces recreation](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/150)

### What It Tests

This is the VCR (pre-recorded HTTP cassette) version of `TestIntKeyfactorCertificateResource_FormatChange`. It validates the core behavior — that changing `certificate_format` does not force recreation — but runs entirely offline using recorded HTTP interactions. No lab connection is needed.

### Test Steps

| Step | Config Change | What Is Validated |
|------|--------------|-------------------|
| 1 | Create with **no** `certificate_format` (default) | Certificate is created. `serial_number`, `thumbprint`, PEM fields populated. `id` captured. |
| 2 | Add `certificate_format = "PEM"` | `id` **unchanged**. PEM fields populated, binary fields absent. |
| 3 | Remove `certificate_format` (back to default) | `id` **unchanged**. PEM fields still populated. |

**Note:** The unit test covers PEM transitions only. Binary format transitions (PFX/JKS/ZIP) require private key recovery from Keyfactor Command, which depends on CA key retention configuration. The integration test exercises the full format matrix on labs that support recovery.

### How to Run

```bash
# Replay mode (no lab needed) — runs with all other unit tests
make testunit

# Or run just this test
go test ./keyfactor/ -run TestUnitKeyfactorCertificateResource_FormatChange -v
```

### Recording a New Cassette

If the test behavior changes or the cassette needs to be re-recorded against a live lab:

```bash
make testunit-record-one TEST_NAME=TestUnitKeyfactorCertificateResource_FormatChange
```

**Note:** The default env file (`~/.env_ses2541`) may have stale `KEYFACTOR_CERTIFICATE_CA_DOMAIN` / `KEYFACTOR_CERTIFICATE_CA_NAME` overrides. If recording fails with a "CA does not exist" error, unset those vars to let the test auto-discover the CA:

```bash
. ~/.env_ses2541 && unset KEYFACTOR_CERTIFICATE_CA_DOMAIN KEYFACTOR_CERTIFICATE_CA_NAME && \
  RECORD_CASSETTES=1 go test ./keyfactor/ -run TestUnitKeyfactorCertificateResource_FormatChange -v -count=1 -timeout 30m
```

### VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers are NOT matched, enabling cross-lab replay)
- **Params file:** Stores the CA, enrollment pattern, and CN used during recording so replay mode constructs identical HCL configs

### Behavior in Replay vs Record Mode

| Mode | How it works |
|------|-------------|
| **Replay** (default) | Loads the cassette YAML and replays recorded HTTP responses. No network access. Skips if cassette file is missing. |
| **Record** (`RECORD_CASSETTES=1`) | Connects to a live lab, runs the full test, and writes all HTTP interactions to the cassette file. Also writes a `.params.json` file with the discovered CA/template/CN values. |
