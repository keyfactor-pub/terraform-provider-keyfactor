terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "~> 2.9"
    }
  }
}

provider "keyfactor" {}

# -----------------------------------------------------------------------
# Discover all store types (used to capture state for code generation)
# -----------------------------------------------------------------------
data "keyfactor_certificate_store_types" "all" {}

# -----------------------------------------------------------------------
# Data source gap fill: singular lookup of one representative store type.
# -----------------------------------------------------------------------
data "keyfactor_certificate_store_type" "k8s_tls_secret" {
  identifier = var.representative_store_type
}

# -----------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------
output "all_store_type_count" {
  description = "Total number of certificate store types on this Command instance."
  value       = length(data.keyfactor_certificate_store_types.all.store_types)
}

output "all_short_names" {
  description = "Short names of all store types."
  value       = data.keyfactor_certificate_store_types.all.store_types[*].short_name
}

output "representative_store_type" {
  description = "Full detail of one representative store type, via the singular data source."
  value = {
    id         = data.keyfactor_certificate_store_type.k8s_tls_secret.id
    name       = data.keyfactor_certificate_store_type.k8s_tls_secret.name
    short_name = data.keyfactor_certificate_store_type.k8s_tls_secret.short_name
  }
}
