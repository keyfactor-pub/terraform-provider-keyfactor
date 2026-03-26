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
