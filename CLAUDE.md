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

| Prefix | Requirements | Makefile Target | Speed |
|--------|-------------|-----------------|-------|
| `TestUnit*` | None (VCR cassettes) | `make testunit` | Fast (~seconds) |
| `TestInt*` | Lab connection env vars only | `make testint` | Medium (~minutes) |
| `TestAcc*` | Legacy tests (many env vars) | `make testacc` | Slow |

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