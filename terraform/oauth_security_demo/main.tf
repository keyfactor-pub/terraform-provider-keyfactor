terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.0"
    }
  }
}

provider "keyfactor" {}

# Look up the "Global" permission set dynamically
data "keyfactor_permission_set" "global" {
  name = "Global"
}

output "role_id" {
  description = "ID of the created OAuth security role."
  value       = keyfactor_oauth_security_role.demo.id
}

output "role_name" {
  description = "Name of the created OAuth security role."
  value       = keyfactor_oauth_security_role.demo.name
}

output "claim_id" {
  description = "ID of the created OAuth security claim."
  value       = keyfactor_oauth_security_claim.demo.id
}

output "association_id" {
  description = "Composite ID of the role-claim association."
  value       = keyfactor_oauth_security_role_claim_association.demo.id
}

output "permission_set_id" {
  description = "ID of the Global permission set."
  value       = data.keyfactor_permission_set.global.id
}
