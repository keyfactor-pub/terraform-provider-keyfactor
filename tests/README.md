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
