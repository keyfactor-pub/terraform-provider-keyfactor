# Look up an application by name
data "keyfactor_application" "by_name" {
  identifier = "My App"
}

# Look up an application by integer ID
data "keyfactor_application" "by_id" {
  identifier = "42"
}

# Reference a managed application resource via the data source
resource "keyfactor_application" "example" {
  name = "My App"
}

data "keyfactor_application" "example" {
  identifier = keyfactor_application.example.name
}

output "store_ids" {
  value = data.keyfactor_application.example.certificate_store_ids
}
