# keyfactor_agents Data Source — Test Documentation

**File:** `keyfactor/data_source_keyfactor_agents_test.go`
**Fixes:** [#52 — Request: orchestration agent data source](https://github.com/keyfactor-pub/terraform-provider-keyfactor/issues/52)

---

## What It Tests

Verifies the `keyfactor_agents` (plural) data source, which returns a list of all orchestrator agents registered in Keyfactor Command with optional client-side filtering.

Also covers the bug fix in `keyfactor_agent` (singular): an index-before-length-check panic when `GetAgent()` returns an empty slice.

---

## Integration Test: `TestIntKeyfactorAgentsDataSource`

Four sub-tests run in sequence using a discovered approved agent:

| Sub-test | Config | What Is Validated |
|----------|--------|-------------------|
| No filters | `data "keyfactor_agents" "test" {}` | At least one agent returned. |
| Status filter | `status_filter = 2` | All returned agents have `status = 2` (Approved). |
| Client machine filter | `client_machine_filter = "<machine>"` | At least one agent matches the discovered machine name (substring match). |
| Capability filter | `capability_filter = "<cap>"` | At least one agent reports the capability used by the discovered agent. |

The client machine and capability sub-tests are skipped if the lab has no agents or no capabilities to discover.

**Prerequisites:**
- Lab connection env vars (`KEYFACTOR_HOSTNAME`, OAuth credentials)
- At least one orchestrator agent registered in the lab

```bash
make testint-run TEST_NAME=TestIntKeyfactorAgentsDataSource
```

---

## Unit Test: `TestUnitKeyfactorAgentsDataSource`

**Cassette:** `keyfactor/testdata/cassettes/agents_data_source.yaml`
**Params:** `keyfactor/testdata/cassettes/agents_data_source.params.json`

Two steps: no-filter (verifies at least one agent returned) and status-filter=2 (verifies all returned agents are approved).

```bash
# Replay (no lab needed)
go test ./keyfactor/ -run TestUnitKeyfactorAgentsDataSource -v

# Or run with all unit tests
make testunit

# Record a new cassette
. ~/.env_ses2541 && RECORD_CASSETTES=1 go test ./keyfactor/ -run TestUnitKeyfactorAgentsDataSource -v -count=1 -timeout 30m
```

---

## VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored)
- **Params file:** Stores `agent_count` recorded at recording time; replay skips if `agent_count == 0`
