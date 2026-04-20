# keyfactor_certificate Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_certificate_test.go`

---

## Table of Contents

- [FormatChange — format changes don't recreate the resource](#formatchange)
- [BothTemplateAndPattern — both attributes accepted simultaneously](#bothtemplateandpattern)
- [NeitherTemplateNorPattern — neither attribute is rejected](#neithertemplatenorpattern)

---

## FormatChange

**Fixes:** [#150 — BUG: Changing certificate_format forces recreation](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/150)

### What It Tests

Verifies that changing the `certificate_format` attribute triggers an **in-place update** rather than forcing resource destruction and recreation.

Prior to the fix, `certificate_format` had a `RequiresReplace()` plan modifier, so any change would destroy the certificate and re-enroll a new one. This was incorrect — `certificate_format` only controls the download/output format, the certificate itself doesn't change.

The fix also validates that when switching formats, exactly the right set of state fields are populated:

| Format | `certificate_pem` | `certificate_chain` | `private_key` | `pfx` | `jks` | `zip` |
|--------|:-----------------:|:-------------------:|:-------------:|:-----:|:-----:|:-----:|
| PEM (or default), cert has archived key | ✓ | ✓ | ✓ | — | — | — |
| PEM (or default), no archived key (CSR) | ✓ | ✓ | — | — | — | — |
| PFX | — | — | — | ✓ | — | — |
| JKS | — | — | — | — | ✓ | — |
| ZIP | — | — | — | — | — | ✓ |

**Regression (ab#82568):** `private_key` was leaking into state for PFX/JKS/ZIP formats. The post-import key recovery block ran unconditionally whenever `plan.PrivateKey.Unknown`, overwriting the null that the format-change block had correctly set. Fixed by guarding recovery with `effectivePlanFmt == "PEM"`.

### Integration Test: `TestIntKeyfactorCertificateResource_FormatChange`

Full 6-step format matrix: default → PEM → PFX → JKS → ZIP → PEM (PFX enrollment, has archived key)

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | No `certificate_format` (default) | Certificate created. `serial_number`, `thumbprint`, PEM fields + `private_key` populated. `id` captured. |
| 2 | `certificate_format = "PEM"` | `id` **unchanged**. PEM fields + `private_key` populated, binary fields absent. |
| 3 | `certificate_format = "PFX"` | `id` **unchanged**. `pfx` populated; PEM fields, `private_key`, `jks`, `zip` absent. |
| 4 | `certificate_format = "JKS"` | `id` **unchanged**. `jks` populated; all other format fields absent. |
| 5 | `certificate_format = "ZIP"` | `id` **unchanged**. `zip` populated; all other format fields absent. |
| 6 | `certificate_format = "PEM"` | `id` **unchanged**. PEM fields + `private_key` populated again. Full round-trip validated. |

**Prerequisites:**
- Lab connection env vars (`KEYFACTOR_HOSTNAME`, OAuth credentials)
- At least one CA and either an enrollment pattern (Command v25+) or a certificate template
- **For PFX/JKS/ZIP steps:** CA must support private key recovery. EJBCA-backed CAs that don't archive keys will fail these steps with "No private key could be found".

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateResource_FormatChange
```

### Unit Test: `TestUnitKeyfactorCertificateResource_FormatChange`

**Cassette:** `keyfactor/testdata/cassettes/certificate_resource_format_change.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_resource_format_change.params.json`

7-step full format matrix for a **PFX-enrolled cert with archived private key**:
default → PEM → PFX → JKS → ZIP → PEM → default

Covers the regression where `private_key` leaked into state for binary formats.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
RECORD_CASSETTES=1 TEST_NAME=TestUnitKeyfactorCertificateResource_FormatChange make testunit-record-one
```

### Unit Test: `TestUnitKeyfactorCertificateResource_FormatChange_CSR`

**Cassette:** `keyfactor/testdata/cassettes/certificate_resource_format_change_csr.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_resource_format_change_csr.params.json`

3-step format test for a **CSR-enrolled cert (no private key in Command)**:
default → PEM → default

Verifies that `private_key` is always null regardless of format when the cert has no archived key (`HasPrivateKey = false`). This is the counterpart to `FormatChange` for the "no private key" path.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
RECORD_CASSETTES=1 TEST_NAME=TestUnitKeyfactorCertificateResource_FormatChange_CSR make testunit-record-one
```

### VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored — enables cross-lab replay)
- **Params file:** Stores the CA, enrollment pattern, and CN used during recording

---

## BothTemplateAndPattern

**Fixes:** [#146 — Provider validation and docs don't match XOR template & pattern](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/146)

### What It Tests

Verifies that specifying **both** `certificate_template` and `certificate_enrollment_pattern` simultaneously is accepted by the provider and results in a successful enrollment.

Prior to the fix, an `xorValidator` required exactly one of the two — specifying both caused a validation error. The Keyfactor Command API allows both; the enrollment pattern takes precedence and the template is used for validation.

### Integration Test: `TestIntKeyfactorCertificateResource_BothTemplateAndPattern`

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Both `certificate_template` and `certificate_enrollment_pattern` set | Certificate created. Both attributes preserved in state. |

**Prerequisites:**
- Lab connection env vars
- Command v25+ with at least one enrollment pattern linked to a template
- Auto-discovers enrollment pattern and its linked template via `discoverEnrollmentPattern()` and `discoverEnrollmentPatternTemplate()`

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateResource_BothTemplateAndPattern
```

### Unit Test: `TestUnitKeyfactorCertificateResource_BothTemplateAndPattern`

**Cassette:** `keyfactor/testdata/cassettes/certificate_resource_both_template_pattern.yaml`
**Params:** `keyfactor/testdata/cassettes/certificate_resource_both_template_pattern.params.json`

```bash
# Replay (no lab needed)
go test ./keyfactor/ -run TestUnitKeyfactorCertificateResource_BothTemplateAndPattern -v

# Record a new cassette
. ~/.env_ses2541 && unset KEYFACTOR_CERTIFICATE_CA_DOMAIN KEYFACTOR_CERTIFICATE_CA_NAME && \
  RECORD_CASSETTES=1 go test ./keyfactor/ -run TestUnitKeyfactorCertificateResource_BothTemplateAndPattern -v -count=1 -timeout 30m
```

---

## NeitherTemplateNorPattern

**Fixes:** [#146 — Provider validation and docs don't match XOR template & pattern](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/146)

### What It Tests

Verifies that specifying **neither** `certificate_template` nor `certificate_enrollment_pattern` is rejected with a clear validation error. The new `atLeastOneOfValidator` preserves this behavior from the old `xorValidator` — at least one must be provided.

### Integration Test: `TestIntKeyfactorCertificateResource_NeitherTemplateNorPattern`

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | Neither attribute set | Provider returns a validation error matching "at least one of". |

```bash
make testint-run TEST_NAME=TestIntKeyfactorCertificateResource_NeitherTemplateNorPattern
```

### Unit Test: `TestUnitKeyfactorCertificateResource_NeitherTemplateNorPattern`

No cassette needed — validation runs before any API calls.

```bash
go test ./keyfactor/ -run TestUnitKeyfactorCertificateResource_NeitherTemplateNorPattern -v
```
