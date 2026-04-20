# Test Suite Refactoring Plan

## Context

The current acceptance tests require a very specifically-configured Keyfactor Command lab with pre-existing resources (specific cert IDs, store IDs, template names, orchestrator agents, etc.) and dozens of environment variables. This makes them impractical to run regularly. The goal is to create:

1. **Unit tests** — no lab needed, using go-vcr cassettes with recorded HTTP responses
2. **Integration tests** — only need connection creds (like `~/.env_ses2541`), with automatic discovery of lab resources (templates, CAs, enrollment patterns, store types, agents)

Priority resources: certificates (resource + data source) and certificate stores.

## Approach

### Phase 1: Test Infrastructure

**File: `keyfactor/test_helpers_test.go`** (new)

Core test infrastructure shared by all tests:

#### 1a. VCR Auth Wrapper for Unit Tests

Implement a `vcrAuthConfig` struct that satisfies the `AuthConfig` interface (`Authenticate()`, `GetHttpClient()`, `GetServerConfig()`). Its `GetHttpClient()` returns an `*http.Client` with the go-vcr recorder's transport injected.

Injection point: after `api.NewKeyfactorClient()` and `keyfactor.NewAPIClient()` return, swap their exported `.AuthClient` field with the VCR wrapper. No library changes needed.

```go
type vcrAuthConfig struct {
    recorder *recorder.Recorder
    server   *auth_providers.Server
}

func (v *vcrAuthConfig) Authenticate() error { return nil }
func (v *vcrAuthConfig) GetHttpClient() (*http.Client, error) {
    return v.recorder.GetDefaultClient(), nil
}
func (v *vcrAuthConfig) GetServerConfig() *auth_providers.Server {
    return v.server
}
```

Helper functions:
- `newVCRProvider(t *testing.T, cassetteName string) (map[string]func() (tfprotov6.ProviderServer, error), func())` — creates a provider with VCR transport, returns factories + cleanup func
- Cassette files stored in `keyfactor/testdata/cassettes/`

#### 1b. Resource Discovery Helpers for Integration Tests

Helper functions that query the live lab to discover available resources. Each accepts an optional env var override — if set, use that value; if not, discover automatically via the API.

```go
// discoverTemplate returns a usable template name.
// Checks KEYFACTOR_CERTIFICATE_TEMPLATE_NAME first, then calls client.GetTemplates()
// and picks the first template that allows PFX enrollment.
func discoverTemplate(t *testing.T, client *api.Client) string

// discoverCA returns "CADomain\\CAName" format.
// Checks KEYFACTOR_CERTIFICATE_CA_DOMAIN + KEYFACTOR_CERTIFICATE_CA_NAME first,
// then calls client.GetCAList() and picks the first available CA.
func discoverCA(t *testing.T, client *api.Client) (domain, name string)

// discoverEnrollmentPattern returns an enrollment pattern name.
// Checks KEYFACTOR_ENROLLMENT_PATTERN first, then calls client.GetEnrollmentPatterns().
func discoverEnrollmentPattern(t *testing.T, client *api.Client) string

// discoverStoreType returns a store type short name.
// Checks KEYFACTOR_CERTIFICATE_STORE_TYPE first, then calls client.ListCertificateStoreTypes().
func discoverStoreType(t *testing.T, client *api.Client) string

// discoverAgent returns agent ID and client machine name.
// Checks KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID first,
// then calls client.GetAgentList() and picks the first approved (Status==2) agent.
func discoverAgent(t *testing.T, client *api.Client) (agentID, clientMachine string)
```

#### 1c. Test Client Factory

```go
// newTestClient creates an authenticated *api.Client for use in integration test setup.
// Uses the same env vars as the provider (KEYFACTOR_HOSTNAME, auth creds, etc.).
// Calls t.Skip() if connection env vars are not set.
func newTestClient(t *testing.T) *api.Client
```

#### 1d. Precheck Functions

```go
// testAccPreCheck validates that required connection env vars are set.
// Calls t.Skip() with a helpful message if KEYFACTOR_HOSTNAME is not set.
func testAccPreCheck(t *testing.T)

// testAccIntegrationPreCheck calls testAccPreCheck and also creates a test client
// to verify connectivity, returning the client for discovery use.
func testAccIntegrationPreCheck(t *testing.T) *api.Client
```

### Phase 2: Add go-vcr Dependency

- Add `gopkg.in/dnaeon/go-vcr.v4` to `go.mod`
- Run `go mod tidy`
- Create `keyfactor/testdata/cassettes/` directory

### Phase 3: Refactor Certificate Tests (Priority 1)

**File: `keyfactor/resource_keyfactor_certificate_test.go`** (refactor in-place)

#### Unit tests (VCR cassettes):
- `TestUnitKeyfactorCertificateResource_PFX` — PFX enrollment with canned API responses
- `TestUnitKeyfactorCertificateResource_CSR` — CSR enrollment with canned responses
- `TestUnitKeyfactorCertificateDataSource` — certificate lookup by ID

Record cassettes by running against a live lab once with `RECORD_CASSETTES=1`, then commit the cassette fixtures. Tests replay without any network.

#### Integration tests (live lab, auto-discovery):
- `TestIntKeyfactorCertificateResource_PFX` — discovers template + CA, enrolls a real cert
- `TestIntKeyfactorCertificateResource_CSR` — same but CSR path
- `TestIntKeyfactorCertificateDataSource` — enrolls a cert first, then reads it back by ID

Pattern for integration tests:
```go
func TestIntKeyfactorCertificateResource_PFX(t *testing.T) {
    client := testAccIntegrationPreCheck(t)
    templateName := discoverTemplate(t, client)
    caDomain, caName := discoverCA(t, client)

    resource.Test(t, resource.TestCase{
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{
            {
                Config: testAccCertPFXConfig(templateName, caDomain, caName),
                Check: resource.ComposeAggregateTestCheckFunc(
                    resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "serial_number"),
                    resource.TestCheckResourceAttrSet("keyfactor_certificate.test", "thumbprint"),
                ),
            },
        },
    })
}
```

**File: `keyfactor/data_source_keyfactor_certificate_test.go`** (refactor)

Remove dependency on pre-existing `TEST_CERTIFICATE_ID`. Integration test creates its own certificate first, then reads it back.

### Phase 4: Refactor Certificate Store Tests (Priority 2)

**File: `keyfactor/resource_keyfactor_certificate_store_test.go`** (refactor)

#### Unit tests (VCR):
- `TestUnitKeyfactorCertificateStoreResource` — create/read/delete with canned responses

#### Integration tests (live lab):
- `TestIntKeyfactorCertificateStoreResource` — discovers store type + agent, creates a real store
- `TestIntKeyfactorCertificateStoreDataSource` — creates a store first, then reads it back

**File: `keyfactor/data_source_keyfactor_certificate_store_test.go`** (refactor)

Remove dependency on pre-existing `TEST_CERTIFICATE_STORE_ID`.

### Phase 5: Refactor Remaining Tests

Apply the same patterns to all other test files:
- `resource_keyfactor_security_identity_test.go` — discover identity via authenticated user
- `resource_keyfactor_security_role_test.go` — already mostly self-contained, just add precheck
- `resource_keyfactor_template_role_binding_test.go` — discover templates dynamically
- `data_source_keyfactor_template_test.go` — discover template dynamically
- `data_source_keyfactor_security_identity_test.go` — use authenticated user identity
- `data_source_keyfactor_security_role_test.go` — `Administrator` role is fine (always exists)
- All OAuth tests — already well-structured, just add proper prechecks
- `resource_keyfactor_certificate_deploy_test.go` — uncomment and implement
- `data_source_keyfactor_permission_set_test.go` — `Global` permission set is fine (always exists)

### Phase 6: Update provider_test.go

Refactor `testAccPreCheck` to actually validate env vars and skip with useful messages. Add build tag support so tests can be run selectively:

```bash
# Unit tests only (no lab needed)
go test ./keyfactor/ -run "TestUnit"

# Integration tests (needs lab connection in env)
go test ./keyfactor/ -run "TestInt"

# All acceptance tests (legacy pattern, needs TF_ACC=1)
go test ./keyfactor/ -run "TestAcc"
```

## Naming Convention

| Prefix | Requirements | Speed |
|--------|-------------|-------|
| `TestUnit*` | None (VCR cassettes) | Fast (~seconds) |
| `TestInt*` | Lab connection env vars | Medium (~minutes) |
| `TestAcc*` | Legacy tests (kept during migration) | Slow |

## Critical Files

| File | Action |
|------|--------|
| `keyfactor/test_helpers_test.go` | New — VCR wrapper, discovery helpers, prechecks |
| `keyfactor/testdata/cassettes/*.yaml` | New — recorded HTTP fixtures |
| `keyfactor/provider_test.go` | Refactor — improve prechecks |
| `keyfactor/resource_keyfactor_certificate_test.go` | Refactor — unit + integration |
| `keyfactor/data_source_keyfactor_certificate_test.go` | Refactor — self-contained |
| `keyfactor/resource_keyfactor_certificate_store_test.go` | Refactor — unit + integration |
| `keyfactor/data_source_keyfactor_certificate_store_test.go` | Refactor — self-contained |
| `go.mod` | Add `gopkg.in/dnaeon/go-vcr.v4` |

## API Methods Used for Discovery

| Resource | Method | Selector |
|----------|--------|----------|
| Templates | `client.GetTemplates()` | First with PFX enrollment allowed |
| CAs | `client.GetCAList()` | First available |
| Enrollment Patterns | `client.GetEnrollmentPatterns()` | First available |
| Store Types | `client.ListCertificateStoreTypes()` | First available |
| Agents | `client.GetAgentList()` | First with `Status==2` (approved) |

## Verification

1. `go test ./keyfactor/ -run "TestUnit" -v` — should pass with no env vars, no network
2. `source ~/.env_ses2541 && go test ./keyfactor/ -run "TestInt" -v` — should pass with just connection creds
3. `go build ./...` — ensure no compilation errors
4. Existing `TestAcc*` tests continue to work during migration
