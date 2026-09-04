terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "~> 2.9"
    }
  }
}

provider "keyfactor" {}

# ---------------------------------------------------------------------------
# Data source gap fill: read one application back and assert it agrees with
# the resource's own state.
# ---------------------------------------------------------------------------
data "keyfactor_application" "no_schedule" {
  identifier = keyfactor_application.no_schedule.name

  depends_on = [keyfactor_application.no_schedule]
}

output "application_datasource_readback_matches" {
  description = "True if data.keyfactor_application's view of no_schedule agrees with the resource's own state."
  value       = data.keyfactor_application.no_schedule.id == keyfactor_application.no_schedule.id
}

output "application_ids" {
  description = "Integer IDs of the demo applications."
  value = {
    no_schedule       = keyfactor_application.no_schedule.id
    immediate         = keyfactor_application.immediate.id
    interval_schedule = keyfactor_application.interval_schedule.id
    daily_schedule    = keyfactor_application.daily_schedule.id
    weekly_schedule   = keyfactor_application.weekly_schedule.id
    monthly_schedule  = keyfactor_application.monthly_schedule.id
    exactly_once      = keyfactor_application.exactly_once.id
  }
}

output "application_store_counts" {
  description = "Number of certificate stores currently assigned to each application."
  value = {
    no_schedule       = keyfactor_application.no_schedule.store_count
    immediate         = keyfactor_application.immediate.store_count
    interval_schedule = keyfactor_application.interval_schedule.store_count
    daily_schedule    = keyfactor_application.daily_schedule.store_count
    weekly_schedule   = keyfactor_application.weekly_schedule.store_count
    monthly_schedule  = keyfactor_application.monthly_schedule.store_count
    exactly_once      = keyfactor_application.exactly_once.store_count
  }
}
