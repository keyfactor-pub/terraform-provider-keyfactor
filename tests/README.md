# Test Documentation

This directory documents the test suite for the Keyfactor Terraform provider. Each file covers the tests for a specific resource or data source.

For general test infrastructure (VCR cassettes, discovery helpers, env vars, Makefile targets), see [CLAUDE.md](../CLAUDE.md).

## Index

| File | Resource / Data Source | Issues |
|------|------------------------|--------|
| [certificate_resource.md](certificate_resource.md) | `keyfactor_certificate` resource | [#150](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/150), [#146](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/146) |
| [agents_data_source.md](agents_data_source.md) | `keyfactor_agents` data source | [#52](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/52) |
| [application_resource.md](application_resource.md) | `keyfactor_application` resource | — |
| [application_data_source.md](application_data_source.md) | `keyfactor_application` data source | — |
| [pam_provider_resource.md](pam_provider_resource.md) | `keyfactor_pam_provider` resource | — |
| [pam_provider_data_source.md](pam_provider_data_source.md) | `keyfactor_pam_provider` data source | — |
| [pam_provider_type_resource.md](pam_provider_type_resource.md) | `keyfactor_pam_provider_type` resource | — |
| [pam_provider_type_data_source.md](pam_provider_type_data_source.md) | `keyfactor_pam_provider_type` data source | — |
| [security_identity_resource.md](security_identity_resource.md) | `keyfactor_identity` resource | — |
| [security_identity_data_source.md](security_identity_data_source.md) | `keyfactor_identity` data source | — |

## Test Tiers

| Prefix | Requirements | Makefile Target |
|--------|-------------|-----------------|
| `TestUnit*` | None (VCR cassettes) | `make testunit` |
| `TestInt*` | Lab connection env vars | `make testint` |
| `TestAcc*` | Legacy tests (many env vars) | `make testacc` |

## VCR Cassette Coverage

Every resource and data source has a `TestUnit*` test backed by a VCR cassette. Cassette files live in `keyfactor/testdata/cassettes/` and are committed to the repo.

| Cassette name | Test function(s) |
|---------------|-----------------|
| `certificate_resource_pfx` | `TestUnitKeyfactorCertificateResource_PFX` |
| `certificate_resource_csr` | `TestUnitKeyfactorCertificateResource_CSR` |
| `certificate_data_source` | `TestUnitKeyfactorCertificateDataSource` |
| `certificate_store_resource` | `TestUnitKeyfactorCertificateStoreResource` |
| `certificate_store_data_source` | `TestUnitKeyfactorCertificateStoreDataSource` |
| `certificate_store_type_resource` | `TestUnitKeyfactorCertificateStoreTypeResource` |
| `certificate_store_type_data_source` | `TestUnitKeyfactorCertificateStoreTypeDataSource` |
| `certificate_store_types_data_source` | `TestUnitKeyfactorCertificateStoreTypesDataSource` |
| `agent_data_source` | `TestUnitKeyfactorAgentDataSource` |
| `permission_set_data_source` | `TestUnitKeyfactorPermissionSetDataSource` |
| `security_role_resource` | `TestUnitKeyfactorSecurityRoleResource` |
| `security_role_data_source` | `TestUnitKeyfactorSecurityRoleDataSource` |
| `security_identity_resource` | `TestUnitKeyfactorIdentityResource` |
| `security_identity_data_source` | `TestUnitKeyfactorIdentityDataSource` |
| `application_resource` | `TestUnitKeyfactorApplicationResource` |
| `application_data_source` | `TestUnitKeyfactorApplicationDataSource` |
| `pam_provider_resource` | `TestUnitKeyfactorPAMProviderResource` |
| `pam_provider_data_source` | `TestUnitKeyfactorPAMProviderDataSource` |
| `pam_provider_type_resource` | `TestUnitKeyfactorPAMProviderTypeResource` |
| `pam_provider_type_data_source` | `TestUnitKeyfactorPAMProviderTypeDataSource` |
| `oauth_security_claim_resource` | `TestUnitKeyfactorOAuthClaimResource` |
| `oauth_security_claim_data_source` | `TestUnitKeyfactorOAuthSecurityClaimDataSource` |
| `oauth_security_role_resource` | `TestUnitKeyfactorOAuthRoleResource` |
| `oauth_security_role_data_source` | `TestUnitKeyfactorOAuthSecurityRoleDataSource` |
| `oauth_security_role_claim_association_resource` | `TestUnitKeyfactorOAuthSecurityRoleClaimAssociationResource` |
| `enrollment_pattern_data_source` | `TestUnitKeyfactorEnrollmentPatternDataSource` *(v25+ only)* |

## Refreshing Cassettes

Cassettes must be re-recorded when the Command API response shapes change (new fields, renamed fields, etc.) or when a major Command version upgrade is deployed to the lab.

### Refresh a single cassette

```bash
# Re-record one specific cassette (e.g. oauth_security_claim_resource)
make testunit-record-oauth-claim

# Generic form — any TestUnit* test name
make testunit-record-one TEST_NAME=TestUnitKeyfactorOAuthClaimResource
```

### Refresh all cassettes at once

```bash
# Re-record every cassette in sequence (requires lab connection)
make testunit-record-all
```

`testunit-record-all` runs each individual record target in sequence. The `enrollment_pattern_data_source` cassette additionally requires `TF_ACC=1` (set automatically by its target) and Command v25+.

### How recording works

1. Set `RECORD_CASSETTES=1` and provide real lab credentials via `KEYFACTOR_ENV_FILE` (default `~/.env_ses2541`).
2. The VCR recorder captures all HTTP interactions to `keyfactor/testdata/cassettes/<name>.yaml`.
3. A companion `<name>.params.json` file stores the values used during recording (names, IDs, etc.) so the replay config can reconstruct the exact same HCL.
4. Commit both `.yaml` and `.params.json` files to the repo.

### When cassettes go stale

Signs that cassettes need re-recording:
- `TestUnit*` tests fail with JSON decode errors or unexpected field values.
- A Command API version bump adds or renames response fields.
- A resource/data source implementation changes how it reads state.

Run `make testunit` to confirm which cassettes are stale, then re-record only those (or run `make testunit-record-all` to refresh everything).
