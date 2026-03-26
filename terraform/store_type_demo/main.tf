terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.0"
    }
  }
}

provider "keyfactor" {}

# -----------------------------------------------------------------------
# Discover all store types (used to capture state for code generation)
# -----------------------------------------------------------------------
data "keyfactor_certificate_store_types" "all" {}

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
