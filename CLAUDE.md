# CLAUDE.md — Project Instructions for Claude Code

## Build & Vendor

- **Always use `./vendor_dev.sh`** instead of `go mod vendor` or `make vendor` directly. This script runs `make vendor` and then symlinks local development copies of `keyfactor-go-client`, `keyfactor-go-client-sdk`, and `kfc-auth` into the vendor directory.
- After modifying `go.mod`, run `go mod tidy` then `./vendor_dev.sh`.
- The local library paths are:
  - `~/GolandProjects/keyfactor-go-client` → `vendor/github.com/Keyfactor/keyfactor-go-client`
  - `~/GolandProjects/kfc-auth` → `vendor/github.com/Keyfactor/keyfactor-auth-client-go`

## Testing

- Run `go build ./...` to verify compilation after changes.
- Run `gofmt -w <file>` after editing Go files.
- Bugs in `keyfactor-go-client` or `keyfactor-go-client-sdk` may be encountered and should be fixed in-place (they are symlinked via vendor_dev.sh).

### Test Tiers

| Prefix | Requirements | Makefile Target | Typical Duration |
|--------|-------------|-----------------|-----------------|
| `TestUnit*` | None (VCR cassettes) | `make testunit` | ~4m36s total (65 pass, 2 skip) |
| `TestInt*` | Lab connection env vars only | `make testint-check` | ~117m total (57 pass, 4 fail, 1 skip); use `-timeout 180m` |
| `TestAcc*` | Legacy tests (many env vars) | `make testacc` | Slow (not recently measured) |

**Note:** `make testint-check` uses `-timeout 120m` by default. The full suite takes ~117 minutes and
occasionally hits this limit. If tests are timing out, set `TESTARGS="-timeout 180m"` or run
individual test groups. The 4 failures above are known lab constraints, not code bugs (see below).

#### Slowest individual integration tests (measured on int25-4-1.kftestlab.com, April 2026)

| Test | Duration | Notes |
|------|----------|-------|
| `TestIntKeyfactorCertificateResource_PFX_KeyTypes` | 957s (16m) | FAIL — RSA-8192 hits lab timeout; sub-tests ECC/Ed* pass |
| `TestIntKeyfactorCertificateResource_SANs` | 530s (9m) | Multiple enroll/renew/revoke cycles |
| `TestIntKeyfactorCertificateResource_CSR_KeyTypes` | 501s (8m) | 8 key type sub-tests × ~60s each |
| `TestIntKeyfactorCertificateResource_FormatChange` | 326s (5m) | PEM→PFX format switch lifecycle |
| `TestIntKeyfactorCertificateDeployResource` | 231s (4m) | K8S store create + deploy + inventory poll |
| `TestIntKeyfactorAgentsDataSource` | 199s (3m) | Polls agent heartbeat |
| `TestIntKeyfactorApplicationResource` | 172s (3m) | Full CRUD + multiple schedule variants |
| `TestIntKeyfactorCertificateResource_CollectionIdInPlaceUpdate` | 163s (3m) | Creates collection, enrolls, updates |
| `TestIntKeyfactorCertificateResource_PFX_Metadata` | 153s (3m) | Metadata lifecycle with drift check |
| `TestIntKeyfactorCertificateStoreTypesDataSource` | 148s (2m) | Large store type enumeration |

#### Known integration test failures (lab constraints, not code bugs)

| Test | Duration | Failure reason |
|------|----------|---------------|
| `TestIntKeyfactorCertificateTemplateDataSourceLegacy` | 52s | Transient OAuth "no route to host" during post-apply plan |
| `TestIntKeyfactorCertificateAuthorityResourceUpdate` | 88s | CA deletion blocked: CA has associated certificates in lab |
| `TestIntKeyfactorCertificateResource_PFX_KeyTypes` | 957s | RSA-8192 PFX enrollment times out on EJBCA lab |
| `TestIntKeyfactorCertificateResource_CSR_Metadata` | 66s | Transient lab error (metadata assertion) |

### Running Tests

```bash
# Unit tests (no network needed)
make testunit

# Integration tests (auto-discover lab resources, just need connection creds)
make testint

# Integration tests with -count=1 (no caching)
make testint-check

# Use a different env file
KEYFACTOR_ENV_FILE=~/.env_other make testint
```

The default env file is `~/.env_ses2541` (set via `KEYFACTOR_ENV_FILE` in the Makefile).

### Integration Test Design

Integration tests (`TestInt*`) auto-discover lab resources using helper functions in `keyfactor/test_helpers_test.go`:

- **`discoverTemplate`** — finds a usable certificate template (prefers non-approval templates)
- **`discoverCA`** — finds a certificate authority
- **`discoverEnrollmentPattern`** — finds enrollment patterns (prefers "Default Pattern"); returns `""` for pre-v25 labs
- **`discoverEnrollmentPatternTemplate`** — returns the template name linked to a given enrollment pattern
- **`discoverStoreType`** — finds a certificate store type (prefers K8S types)
- **`discoverStoreTypeForAgent`** — cross-references agent capabilities with available store types
- **`discoverAgent`** — finds an approved orchestrator agent (Status==2), logs capabilities
- **`discoverSecurityIdentity`** — finds an existing security identity via the API
- **`discoverOAuthAuthScheme`** — returns OAuth auth scheme (defaults to "System")

Each discovery function checks for an env var override first, then falls back to API discovery. Tests call `t.Skip()` if required resources aren't available in the lab.

### Environment Variables

Only connection credentials are required for `TestInt*` tests:
- `KEYFACTOR_HOSTNAME` — Command server hostname
- `KEYFACTOR_AUTH_CLIENT_ID`, `KEYFACTOR_AUTH_CLIENT_SECRET`, `KEYFACTOR_AUTH_TOKEN_URL` — OAuth credentials
- `KEYFACTOR_SKIP_VERIFY` — set to `true` to skip TLS verification

Optional overrides (auto-discovered if not set):
- `KEYFACTOR_CERTIFICATE_TEMPLATE_NAME`, `KEYFACTOR_CERTIFICATE_CA_DOMAIN`/`KEYFACTOR_CERTIFICATE_CA_NAME`
- `KEYFACTOR_ENROLLMENT_PATTERN`, `KEYFACTOR_CERTIFICATE_STORE_TYPE`
- `KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID`, `KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE`
- `KEYFACTOR_DOMAIN`, `KEYFACTOR_USERNAME` (for identity tests)
- `KEYFACTOR_OAUTH_SECURITY_CLAIM_AUTHENTICATION_SCHEME` (for OAuth claim tests)

## Project Structure

- Provider code: `keyfactor/provider.go`
- Resources: `keyfactor/resource_keyfactor_*.go`
- Data sources: `keyfactor/data_source_keyfactor_*.go`
- Helpers: `keyfactor/helpers.go`
- Auth library: `~/GolandProjects/kfc-auth/auth_providers/`
- Go client v3: `~/GolandProjects/keyfactor-go-client/v3/api/`

## Code Style

- Follow existing patterns in the codebase.
- Use `tflog` for logging inside provider code.
- Use `LogFunctionEntry`, `LogFunctionCall`, `LogFunctionReturned`, `LogFunctionExit` helpers for function tracing.
- Schema descriptions should reference environment variables using `EnvVarUsage` format string.

## Operations
- Operations/commands that are "useful" and/or repeated should be added to the GNUmakefile
- Prioritize using makefile targets over raw bash commands

## Demo / Lab Lifecycle Test Strategy

When validating provider changes against a real lab, always follow this lifecycle:

```
plan → apply → import-all → drift-check → destroy
```

1. **plan** — `make lab-plan` or `terraform plan` — verify no unexpected changes
2. **apply** — `make lab-apply` or `terraform apply` — create/update resources
3. **import-all** — `make lab-import` — import every resource by its real ID; verifies ImportState round-trip
4. **drift-check** — `make lab-plan` again after import — the only "to change" lines should be write-only fields (e.g., `enrollment_password`, `csr`, `key_password`, `pfx`, `jks`, `zip`, `private_key` if no key recovery); no `to add` or `to destroy`
5. **destroy** — `make lab-destroy` — clean up; verify plan shows 0 resources after

Use `make lifecycle` / `make lab-lifecycle` Makefile targets when available. Never use ad-hoc shell scripts for lifecycle operations — add a Makefile target instead.

## Agent Delegation

- **All code changes** (features, bug fixes, tests, refactors) must be implemented by the `k8s-orchestrator-dev` subagent — never written directly in the main conversation.
- **All new automation** (curl API calls, test sequences, lifecycle steps) must be added as Makefile targets. No one-off shell scripts.
- The main conversation is for coordination, review, planning, and memory management only.