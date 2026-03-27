# -----------------------------------------------------------------------
# Example 1: No inventory schedule — application is a container only.
# -----------------------------------------------------------------------
resource "keyfactor_application" "no_schedule" {
  name = "Demo No Schedule${var.suffix}"
}

# -----------------------------------------------------------------------
# Example 2: Immediate — triggers an inventory run as soon as the
# application is created. The server may convert this to an ExactlyOnce
# entry on subsequent reads; a reconcile step handles that drift.
# -----------------------------------------------------------------------
resource "keyfactor_application" "immediate" {
  name               = "Demo Immediate${var.suffix}"
  schedule_immediate = true
}

# -----------------------------------------------------------------------
# Example 3: Interval-based schedule — inventory runs every 60 minutes.
# -----------------------------------------------------------------------
resource "keyfactor_application" "interval_schedule" {
  name                      = "Demo Interval Schedule${var.suffix}"
  schedule_interval_minutes = var.interval_minutes
}

# -----------------------------------------------------------------------
# Example 4: Daily schedule — inventory runs at 23:30 UTC each day.
# The server normalizes the date portion to the next occurrence after each
# run; only the time-of-day (T23:30:00Z) is meaningful.
# -----------------------------------------------------------------------
resource "keyfactor_application" "daily_schedule" {
  name                = "Demo Daily Schedule${var.suffix}"
  schedule_daily_time = var.daily_time
}

# -----------------------------------------------------------------------
# Example 5: Weekly schedule — inventory runs on Monday and Thursday at
# 02:00 UTC.
# -----------------------------------------------------------------------
resource "keyfactor_application" "weekly_schedule" {
  name                 = "Demo Weekly Schedule${var.suffix}"
  schedule_weekly_days = var.weekly_days
  schedule_weekly_time = var.weekly_time
}

# -----------------------------------------------------------------------
# Example 6: Monthly schedule — inventory runs on the 1st of each month
# at 04:00 UTC.
# -----------------------------------------------------------------------
resource "keyfactor_application" "monthly_schedule" {
  name                  = "Demo Monthly Schedule${var.suffix}"
  schedule_monthly_day  = var.monthly_day
  schedule_monthly_time = var.monthly_time
}

# -----------------------------------------------------------------------
# Example 7: ExactlyOnce — inventory runs exactly once at the specified
# UTC datetime. After it fires the server clears the schedule.
# -----------------------------------------------------------------------
resource "keyfactor_application" "exactly_once" {
  name                       = "Demo Exactly Once${var.suffix}"
  schedule_exactly_once_time = "2025-06-01T06:00:00Z"
}
