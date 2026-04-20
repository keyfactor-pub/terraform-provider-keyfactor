# `keyfactor_identity` Resource Tests

## Overview

Tests for the `keyfactor_identity` resource (create/update/delete lifecycle for Keyfactor security identities backed by Active Directory).

## Test Functions

| Function | Tier | Description |
|----------|------|-------------|
| `TestUnitKeyfactorIdentityResource` | Unit | VCR cassette replay — creates `KEYFACTOR\Guest`, verifies, destroys |
| `TestAccKeyfactorIdentityResource` | Acc | Creates identity with one role, updates to two roles, updates to no roles |
| `TestIntKeyfactorIdentityResource` | Int | Creates identity with `Administrator` role, then removes all roles |

## Unit Test

**Cassette:** `keyfactor/testdata/cassettes/security_identity_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/security_identity_resource.params.json`

Records against a Windows AD–backed lab (basic auth). Uses `KEYFACTOR\Guest` (a standard domain account that is not pre-imported into Keyfactor).

```bash
# Replay (no lab needed)
make testunit

# Re-record (requires kftrain or similar basic-auth AD lab)
KEYFACTOR_ENV_FILE=~/.env_kftrain make testunit-record-one TEST_NAME=TestUnitKeyfactorIdentityResource
```

**Notes:**
- `identity_type` and `valid` are only populated by `Read`, not `Create`; the unit test omits those checks.
- The resource has known post-refresh drift (computed fields, `roles []` vs `null`) — `ExpectNonEmptyPlan: true` is set on the step.
- Requires an AD-backed lab; the OAuth lab does not support AD identity creation.

## Integration Test

```bash
make testint
```

Requires only `KEYFACTOR_HOSTNAME` + auth credentials. Auto-discovers an existing security identity via `discoverSecurityIdentity`.

**Note:** The OAuth lab (`ses2541`) has no Windows AD identities — the integration test is skipped there.

## Acceptance Test

Requires environment variables:
- `KEYFACTOR_SECURITY_IDENTITY_ACCOUNTNAME` — e.g. `COMMAND\\terraformer`
- `KEYFACTOR_SECURITY_IDENTITY_ROLE1`, `KEYFACTOR_SECURITY_IDENTITY_ROLE2`
