# Application with an interval-based inventory schedule
resource "keyfactor_application" "interval" {
  name                      = "My App"
  overwrite_schedules       = false
  schedule_interval_minutes = 60
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
