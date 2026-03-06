---
page_title: "keyfactor_application Resource - terraform-provider-keyfactor"
subcategory: ""
description: |-
  Manages a Keyfactor Command Application (certificate store container). Applications group certificate stores together and define an optional inventory schedule that applies to all member stores. Requires Keyfactor Command v25.0+.
---

# keyfactor_application (Resource)

Manages a Keyfactor Command Application (certificate store container).

Applications group certificate stores together and define an optional inventory schedule that applies to all member stores.

> [!NOTE]
> Applications are only available in Keyfactor Command v25.0+

## Example Usage

```terraform
# Application with an interval-based inventory schedule
resource "keyfactor_application" "interval" {
  name                       = "My App"
  overwrite_schedules        = false
  schedule_interval_minutes  = 60
}

# Application with a daily inventory schedule
resource "keyfactor_application" "daily" {
  name                = "My Daily App"
  overwrite_schedules = true
  schedule_daily_time = "2024-01-01T02:00:00Z" # Server uses only the time portion (02:00 UTC daily)
}

# Minimal application (no schedule)
resource "keyfactor_application" "minimal" {
  name = "My Minimal App"
}
```

## Schema

### Required

- `name` (String) Name of the application (certificate store container).

### Optional

- `overwrite_schedules` (Boolean) When true, the application schedule overwrites the schedules of all member certificate stores. Defaults to `false`.
- `schedule_daily_time` (String) Inventory schedule daily time as an ISO 8601 datetime string (e.g. `2024-01-01T23:30:00Z`). The server uses only the time-of-day portion — the date is normalized to the next scheduled occurrence. Mutually exclusive with `schedule_interval_minutes`.
- `schedule_interval_minutes` (Number) Inventory schedule interval in minutes. Set to a positive integer to use an interval-based schedule. Mutually exclusive with `schedule_daily_time`.

### Read-Only

- `id` (String) Keyfactor Command application ID.
- `store_count` (Number) Number of certificate stores currently assigned to this application.
