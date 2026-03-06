# Test Configuration Gap Plan

## Known Limitation: `id` Attribute and the SDKv2 Test Harness

The Terraform SDKv2 test harness (`terraform-plugin-sdk/v2/helper/resource`) requires every
resource and data source to have an `id` attribute in state. The provider uses the Terraform
Plugin Framework (tfsdk v0.10.0), which does not automatically inject an `id` attribute.

Most resources and data sources already have an explicit `"id"` schema attribute. However,
**the `keyfactor_agent` data source does not**. This means any test using the SDKv2 test
harness for this data source will fail with:

```
no "id" found in attributes
```

### Affected Resources/Data Sources

| Type | Name | Has `id` attr | Status |
|------|------|---------------|--------|
| Data Source | `keyfactor_agent` | **NO** | Blocked until `id` is added |
| All others | * | Yes | OK |

### Resolution Path

Adding a computed `id` attribute requires:
1. Adding `"id"` to the schema in `data_source_keyfactor_agent.go`
2. Adding a `TfId types.String \`tfsdk:"id"\`` field to the `CommandAgent` model struct
3. Setting `TfId` = `AgentId` before writing state (same `syncTfId()` pattern used for certificates)

This is a provider code change (not just a test change). It will be done as a prerequisite
to Phase 1 below, following the same pattern established for the certificate resource/data source.

Alternatively, migrating to `terraform-plugin-testing` would remove the `id` requirement entirely,
but that requires upgrading `terraform-plugin-framework` from v0.10.0 to v1.x — a larger effort
planned for the future.

**Any new data source or resource added to the provider MUST include an `"id"` computed attribute
in its schema to be compatible with the current test framework.**

---

## Inventory Summary

### Data Sources (10 total)

| # | Data Source | Test File | TestAcc | TestInt | Gaps |
|---|---|---|---|---|---|
| 1 | agent | **MISSING** | - | - | No test file; missing `id` attr (blocked) |
| 2 | enrollment_pattern | **MISSING** | - | - | No test file |
| 3 | certificate | Yes | Yes | Yes | TestInt could check more attrs (subject, metadata) |
| 4 | certificate_store | Yes | Yes | Yes | TestInt could check `properties`, `approved` |
| 5 | certificate_template | Yes | Yes | Yes | TestInt only checks 4 attrs; missing `key_size`, `key_type`, `requires_approval` |
| 6 | oauth_security_claim | Yes | Yes | Yes | Good coverage |
| 7 | oauth_security_role | Yes | Yes | Yes | TestInt doesn't check `permission_set_id`, `permissions`, `email_address` |
| 8 | permission_set | Yes | Yes | Yes | Could verify `permissions.#` > 0 |
| 9 | security_identity | Yes | Yes | Yes | Skips on OAuth-only labs -- acceptable |
| 10 | security_role | Yes | Yes | Yes | Good coverage |

### Resources (10 total)

| # | Resource | Test File | TestAcc | TestInt | Gaps |
|---|---|---|---|---|---|
| 1 | certificate | Yes | 3 TestAcc | 2 TestInt | TestInt missing: update step, metadata, subject, SANs |
| 2 | certificate_deploy | Yes | **Commented out** | - | Entire file commented out |
| 3 | certificate_store | Yes | Yes | Yes | TestInt missing: update step, properties check |
| 4 | certificate_store_type | **N/A** | - | - | **Resource source entirely commented out** -- skip |
| 5 | oauth_security_claim | Yes | 4 TestAcc | 1 TestInt | TestInt missing: update, replace-on-uneditable, import |
| 6 | oauth_security_role | Yes | 3 TestAcc | 1 TestInt | TestInt missing: update, duplicate perms, import |
| 7 | oauth_role_claim_assoc | Yes | Yes | Yes | TestInt missing: update (role swap) |
| 8 | security_identity | Yes | Yes | Yes | TestInt missing: multi-step (add/remove roles); skips on OAuth labs |
| 9 | security_role | Yes | Yes | Yes | TestInt missing: multi-step (add/remove permissions) |
| 10 | template_role_binding | Yes | Yes | Yes | Limited by Policies bug; uses ExpectError -- acceptable |

---

## Phase Plan

### Phase 1: Data Source -- Agent (NEW)

**Prerequisite**: Add `id` computed attribute to `data_source_keyfactor_agent.go` and
`TfId` field to `CommandAgent` model (same pattern as certificate).

**File**: `keyfactor/data_source_keyfactor_agent_test.go` (new)

**Tests**:
- `TestIntKeyfactorAgentDataSource` -- use `discoverAgent()` to get GUID, look up via `agent_identifier`
- Second test step: look up by `client_machine` name instead of GUID
- Verify: `agent_id`, `client_machine`, `username`, `status`, `version`, `capabilities`, `thumbprint`

**Helpers** (in `test_helpers_test.go`):
- `testAccAgentDataSourceConfig(identifier string) string`

**Commit after passing.**

---

### Phase 2: Data Source -- Enrollment Pattern (NEW)

**File**: `keyfactor/data_source_keyfactor_enrollment_pattern_test.go` (new)

**Tests**:
- `TestIntKeyfactorEnrollmentPatternDataSource` -- use `discoverEnrollmentPattern()`, skip if empty (pre-v25)
- Look up by name, verify: `id`, `name`, `template`, `allowed_enrollment_types`, `template_default`
- Second lookup by ID (from first result) to test the numeric ID path

**Helpers** (in `test_helpers_test.go`):
- `testAccEnrollmentPatternDataSourceConfig(identifier string) string`

**Commit after passing.**

---

### Phase 3: Data Source -- Certificate Template (ENHANCE)

**File**: `keyfactor/data_source_keyfactor_template_test.go` (modify)

**Scope**: Enhance `TestIntKeyfactorCertificateTemplateDataSource` to check additional attrs:
- `key_size`, `key_type`, `forest_root`, `requires_approval`, `key_usage`
- `allowed_enrollment_types`, `template_regexes.#`

**Commit after passing.**

---

### Phase 4: Data Source -- Certificate (ENHANCE)

**File**: `keyfactor/data_source_keyfactor_certificate_test.go` (modify)

**Scope**: Enhance `TestIntKeyfactorCertificateDataSource` to check additional attrs:
- `subject.%`, `metadata.%`, `certificate_authority`, `certificate_template`, `keyfactor_request_id`

**Commit after passing.**

---

### Phase 5: Data Source -- Certificate Store (ENHANCE)

**File**: `keyfactor/data_source_keyfactor_certificate_store_test.go` (modify)

**Scope**: Enhance `TestIntKeyfactorCertificateStoreDataSource` to check:
- `approved`, `properties.%`, `agent_assigned`

**Commit after passing.**

---

### Phase 6: Data Source -- OAuth Security Role (ENHANCE)

**File**: `keyfactor/data_source_keyfactor_oauth_security_role_test.go` (modify)

**Scope**: Enhance `TestIntKeyfactorOAuthSecurityRoleDataSource` to check:
- `permission_set_id`, `email_address`, `permissions.#`

**Commit after passing.**

---

### Phase 7: Data Source -- Permission Set (ENHANCE)

**File**: `keyfactor/data_source_keyfactor_permission_set_test.go` (modify)

**Scope**: Enhance `TestIntKeyfactorPermissionSetDataSource`:
- Verify `permissions.#` > 0 using `TestMatchResourceAttr` with a regex like `[1-9][0-9]*`

**Commit after passing.**

---

### Phase 8: Resource -- Certificate (ENHANCE)

**File**: `keyfactor/resource_keyfactor_certificate_test.go` (modify)

**Scope**:
- Enhance `TestIntKeyfactorCertificateResource_PFX` to check: `id`, `keyfactor_request_id`,
  `certificate_authority`, `certificate_template`/`certificate_enrollment_pattern`
- Add `TestIntKeyfactorCertificateResource_PFX_WithSubject` -- uses `subject` block + SANs + metadata
- Add update step to PFX test (change metadata, verify no replacement)

**Helpers** (in `test_helpers_test.go`):
- `testAccCertPFXConfigWithSubject(templateName, ca, cn, dnsSans, metadata string) string`

**Commit after passing.**

---

### Phase 9: Resource -- Certificate Store (ENHANCE)

**File**: `keyfactor/resource_keyfactor_certificate_store_test.go` (modify)

**Scope**:
- Enhance `TestIntKeyfactorCertificateStoreResource` to check: `approved`, `properties.%`
- Add update step (change `store_path`, verify replacement or update behavior)

**Commit after passing.**

---

### Phase 10: Resource -- Certificate Deploy (REWRITE)

**File**: `keyfactor/resource_keyfactor_certificate_deploy_test.go` (uncomment + rewrite)

**Tests**:
- `TestIntKeyfactorCertificateDeployResource` -- creates cert + store, then deploys cert to store
- Uses `discoverCA()`, `discoverTemplate()`/`discoverEnrollmentPattern()`, `discoverAgent()`,
  `discoverStoreTypeForAgent()`
- Verify: `id`, `certificate_id`, `certificate_store_id`, `certificate_alias`

**Helpers** (in `test_helpers_test.go`):
- `testAccCertDeployConfig(certRef, storeRef string) string`

**Commit after passing.**

---

### Phase 11: Resource -- OAuth Security Claim (ENHANCE)

**File**: `keyfactor/resource_keyfactor_oauth_security_claim_test.go` (modify)

**Scope**:
- Add `TestIntKeyfactorOAuthClaimResource_Update` -- create then update description
- Add `TestIntKeyfactorOAuthClaimResource_Import` -- create then ImportState

**Commit after passing.**

---

### Phase 12: Resource -- OAuth Security Role (ENHANCE)

**File**: `keyfactor/resource_keyfactor_oauth_security_role_test.go` (modify)

**Scope**:
- Add `TestIntKeyfactorOAuthRoleResource_Update` -- create then update description + permissions
- Add `TestIntKeyfactorOAuthRoleResource_Import` -- create then ImportState

**Commit after passing.**

---

### Phase 13: Resource -- OAuth Role Claim Association (ENHANCE)

**File**: `keyfactor/resource_keyfactor_oauth_security_role_claim_association_test.go` (modify)

**Scope**:
- Add `TestIntKeyfactorOAuthSecurityRoleClaimAssociationResource_Update` -- swap associated role (role1 to role2)

**Commit after passing.**

---

### Phase 14: Resource -- Security Identity (ENHANCE)

**File**: `keyfactor/resource_keyfactor_security_identity_test.go` (modify)

**Scope**:
- Add `TestIntKeyfactorIdentityResource_MultiRole` -- create with 1 role, update to 2 roles, update to 0 roles
- Skips on OAuth-only labs (no Windows identities available)

**Commit after passing.**

---

### Phase 15: Resource -- Security Role (ENHANCE)

**File**: `keyfactor/resource_keyfactor_security_role_test.go` (modify)

**Scope**:
- Add `TestIntKeyfactorRoleResource_Update` -- create with 0 permissions, update to add
  `AdminPortal:Read` + `API:Read`, update back to 0
- Verify `description`, `permissions.#` at each step

**Commit after passing.**

---

### Phase 16: Resource -- Template Role Binding (NO CHANGE)

Already has TestInt with `ExpectError` for the Policies bug (keyfactor-go-client v3
`UpdateTemplateArg` struct missing `Policies` field required by Command v25+).

No actionable enhancement until the client library is updated. **Skip.**

---

### Phase 17: Resource -- Certificate Store Type (NO CHANGE)

Resource source code (`resource_keyfactor_certificate_store_type.go`) is entirely commented out.
This is an unimplemented feature, not a test gap. **Skip.**

---

## Execution Order Rationale

1. **Phases 1-2** (new test files) -- highest value, fill completely missing coverage
2. **Phases 3-7** (data source enhancements) -- low risk, quick wins, improve attribute coverage
3. **Phases 8-10** (core resource enhancements) -- certificate and store are the most important resources
4. **Phases 11-15** (remaining resource enhancements) -- add update/import steps to existing TestInt tests
5. **Phases 16-17** (skip) -- blocked by known limitations

## Test Helpers Summary

New helpers to add in `keyfactor/test_helpers_test.go`:

| Helper | Used By |
|--------|---------|
| `testAccAgentDataSourceConfig(identifier)` | Phase 1 |
| `testAccEnrollmentPatternDataSourceConfig(identifier)` | Phase 2 |
| `testAccCertPFXConfigWithSubject(template, ca, cn, dnsSans, metadata)` | Phase 8 |
| `testAccCertDeployConfig(certRef, storeRef)` | Phase 10 |

## Verification

After each phase:

```bash
# Run just the new/modified tests
make testint-check

# Verify compilation
go build ./...
```

After all phases:

```bash
# Full integration test suite
make testint

# Full unit test suite (no network)
make testunit
```
