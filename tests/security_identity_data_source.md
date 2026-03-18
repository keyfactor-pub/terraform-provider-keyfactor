# `keyfactor_identity` Data Source Tests

## Overview

Tests for the `keyfactor_identity` data source (read an existing Keyfactor security identity by account name).

## Test Functions

| Function | Tier | Description |
|----------|------|-------------|
| `TestUnitKeyfactorIdentityDataSource` | Unit | VCR cassette replay — reads `KEYFACTOR\SVC_AppPool` |
| `TestAccKeyfactorSecurityIdentityDataSource` | Acc | Reads identity by domain+username env vars |
| `TestIntKeyfactorSecurityIdentityDataSource` | Int | Reads auto-discovered identity from lab |

## Unit Test

**Cassette:** `keyfactor/testdata/cassettes/security_identity_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/security_identity_data_source.params.json`

Records against a Windows AD–backed lab. Auto-discovers the first valid existing security identity.

```bash
# Replay (no lab needed)
make testunit

# Re-record (requires kftrain or similar basic-auth AD lab)
KEYFACTOR_ENV_FILE=~/.env_kftrain make testunit-record-one TEST_NAME=TestUnitKeyfactorIdentityDataSource
```

**Note:** Requires an AD-backed lab; the OAuth lab returns no AD identities.

## Integration Test

```bash
make testint
```

Requires only `KEYFACTOR_HOSTNAME` + auth credentials. Auto-discovers an existing identity.

## Acceptance Test

Requires:
- `KEYFACTOR_DOMAIN` + `KEYFACTOR_USERNAME` — used to construct the expected `account_name`
