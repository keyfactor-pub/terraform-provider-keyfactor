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

The fix also validates that when switching formats, only the expected format-specific state fields are populated:

- **PEM** (or default): `certificate_pem`, `certificate_chain` set; `pfx`, `jks`, `zip` absent
- **PFX**: `pfx` set; PEM fields and `jks`, `zip` absent
- **JKS**: `jks` set; PEM fields and `pfx`, `zip` absent
- **ZIP**: `zip` set; PEM fields and `pfx`, `jks` absent

### Integration Test: `TestIntKeyfactorCertificateResource_FormatChange`

Full 6-step format matrix: default → PEM → PFX → JKS → ZIP → PEM

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | No `certificate_format` (default) | Certificate created. `serial_number`, `thumbprint`, PEM fields populated. `id` captured. |
| 2 | `certificate_format = "PEM"` | `id` **unchanged**. PEM fields populated, binary fields absent. |
| 3 | `certificate_format = "PFX"` | `id` **unchanged**. `pfx` populated, all other format fields absent. |
| 4 | `certificate_format = "JKS"` | `id` **unchanged**. `jks` populated, all other format fields absent. |
| 5 | `certificate_format = "ZIP"` | `id` **unchanged**. `zip` populated, all other format fields absent. |
| 6 | `certificate_format = "PEM"` | `id` **unchanged**. PEM fields populated again. Full round-trip validated. |

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

3-step flow (default → PEM → default). Binary format transitions are omitted because they require private key recovery, which depends on CA key retention configuration.

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
. ~/.env_ses2541 && unset KEYFACTOR_CERTIFICATE_CA_DOMAIN KEYFACTOR_CERTIFICATE_CA_NAME && \
  RECORD_CASSETTES=1 go test ./keyfactor/ -run TestUnitKeyfactorCertificateResource_FormatChange -v -count=1 -timeout 30m
```

**Note:** The default env file may have stale `KEYFACTOR_CERTIFICATE_CA_DOMAIN` / `KEYFACTOR_CERTIFICATE_CA_NAME` overrides. Unsetting them lets the test auto-discover the CA.

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
