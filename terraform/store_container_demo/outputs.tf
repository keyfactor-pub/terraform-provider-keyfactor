output "application_id" {
  description = "Integer ID of the demo application (also its container ID for certificate stores)."
  value       = keyfactor_application.demo.id
}

output "application_name" {
  description = "Name of the demo application."
  value       = keyfactor_application.demo.name
}

output "container_name_style_id" {
  description = "ID of the container_name-style certificate store."
  value       = keyfactor_certificate_store.container_name_style.id
}

output "application_name_style_id" {
  description = "ID of the application_name-style certificate store."
  value       = keyfactor_certificate_store.application_name_style.id
}

# ---------------------------------------------------------------------------
# Data source gap fill: read back one of the managed stores via
# data.keyfactor_certificate_store and assert it agrees with the resource's
# own state (container assignment in particular, since that's exactly what
# issue #175 breaks).
# ---------------------------------------------------------------------------
data "keyfactor_certificate_store" "container_name_style" {
  id = keyfactor_certificate_store.container_name_style.id

  depends_on = [keyfactor_certificate_store.container_name_style]
}

output "container_name_style_readback_matches" {
  description = "True if the data source's view of the store's container assignment agrees with the resource's own state."
  value       = data.keyfactor_certificate_store.container_name_style.container_id == keyfactor_certificate_store.container_name_style.container_id
}
