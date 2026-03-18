# keyfactor_application Resource — Test Documentation

**File:** `keyfactor/resource_keyfactor_application_test.go`

> **Note:** Applications are only available in Keyfactor Command v25.0+

---

## What It Tests

Verifies full CRUD lifecycle of the `keyfactor_application` resource, including:
- Creating an application with an interval-based inventory schedule
- Updating the interval
- Switching from an interval schedule to a daily schedule
- Destroying the application at cleanup

Also covers `overwrite_schedules` flag behavior (toggling whether the application schedule overwrites member store schedules).

---

## Integration Test: `TestIntKeyfactorApplicationResource`

Three-step lifecycle against a live lab:

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | `schedule_interval_minutes = 60` | Application created; `id` set; `name` and `schedule_interval_minutes` match. |
| 2 | `schedule_interval_minutes = 30` | In-place update; `id` unchanged; interval updated. |
| 3 | `schedule_daily_time = "2023-11-25T23:30:00Z"` | Schedule type switched to daily; time preserved in state (server normalizes date but time portion is compared). |

```bash
make testint-run TEST_NAME=TestIntKeyfactorApplicationResource
```

---

## Integration Test: `TestIntKeyfactorApplicationResourceNoSchedule`

Verifies an application can be created without any schedule configured.

```bash
make testint-run TEST_NAME=TestIntKeyfactorApplicationResourceNoSchedule
```

---

## Unit Test: `TestUnitKeyfactorApplicationResource`

**Cassette:** `keyfactor/testdata/cassettes/application_resource.yaml`
**Params:** `keyfactor/testdata/cassettes/application_resource.params.json`

Three-step flow mirroring the integration test (create with 60-min interval → update to 30-min interval → switch to daily schedule).

| Step | Config | What Is Validated |
|------|--------|-------------------|
| 1 | `schedule_interval_minutes = 60` | `id` set; `name`, `overwrite_schedules`, `schedule_interval_minutes` all match. |
| 2 | `schedule_interval_minutes = 30` | `id` unchanged; interval updated to 30. |
| 3 | `schedule_daily_time = "2023-11-25T23:30:00Z"` | `id` unchanged; `schedule_daily_time` preserved as configured. |

```bash
# Replay (no lab needed)
make testunit

# Record a new cassette
make testunit-record-application
```

---

## VCR Details

- **Cassette format:** go-vcr v4 YAML
- **Matcher:** Method + normalized URL path + query (body/headers ignored)
- **Params file:** Stores `app_name` recorded at recording time; replay uses the same name to construct identical HCL
