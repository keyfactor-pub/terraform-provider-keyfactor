variable "suffix" {
  type        = string
  default     = "_TF"
  description = "Suffix appended to application names to avoid conflicts with existing applications."
}

variable "interval_minutes" {
  type        = number
  default     = 60
  description = "Schedule interval in minutes for the interval_schedule application."
}

variable "daily_time" {
  type        = string
  default     = "2025-01-01T23:30:00Z"
  description = "Daily inventory schedule time (ISO-8601). Only the time-of-day portion is meaningful; the server normalises the date after each run."
}

variable "weekly_days" {
  type        = list(string)
  default     = ["Monday", "Thursday"]
  description = "Days of the week for the weekly_schedule application."
}

variable "weekly_time" {
  type        = string
  default     = "2025-01-01T02:00:00Z"
  description = "Weekly inventory schedule time (ISO-8601). Only the time-of-day portion is meaningful."
}

variable "monthly_day" {
  type        = number
  default     = 1
  description = "Day of the month (1–31) for the monthly_schedule application."
}

variable "monthly_time" {
  type        = string
  default     = "2025-01-01T04:00:00Z"
  description = "Monthly inventory schedule time (ISO-8601). Only the time-of-day portion is meaningful."
}
