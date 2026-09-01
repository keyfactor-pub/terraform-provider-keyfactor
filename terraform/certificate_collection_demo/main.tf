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
# keyfactor_certificate_collection resource under test.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_collection" "demo" {
  name              = "Demo Collection${var.suffix}"
  description       = var.description_override != "" ? var.description_override : "Terraform harness demo collection"
  query             = "IssuedDN -contains \"demo\""
  show_on_dashboard = false
}

# ---------------------------------------------------------------------------
# Data source gap fill: read the collection back by name and assert it
# agrees with the resource's own state.
# ---------------------------------------------------------------------------
data "keyfactor_certificate_collection" "demo" {
  name = keyfactor_certificate_collection.demo.name

  depends_on = [keyfactor_certificate_collection.demo]
}

output "collection_id" {
  description = "Integer ID of the demo certificate collection."
  value       = keyfactor_certificate_collection.demo.id
}

output "datasource_readback_matches" {
  description = "True if data.keyfactor_certificate_collection's view agrees with the resource."
  value       = data.keyfactor_certificate_collection.demo.id == keyfactor_certificate_collection.demo.id
}
