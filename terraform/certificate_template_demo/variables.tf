variable "template_short_name" {
  type        = string
  default     = "AnyCA_lab-role"
  description = "Short name (or integer ID) of an existing certificate template to import. Defaults to the kfclab lab's AnyCA_lab-role template (id 6 per lab inventory)."
}

variable "friendly_name_override" {
  type        = string
  default     = ""
  description = "New friendly_name to apply on lab-update, to exercise Update(). Leave empty (default) to keep the template's current display_name unchanged."
}
