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
# keyfactor_pam_provider full lifecycle against the lab's real
# Hashicorp-Vault PAM provider type.
#
# remote = false here, NOT true. Verified directly against Command 25.5 on
# kfclab (2026-08-07):
#   - remote=true + non-instance-level ProviderTypeParamValues (Host/Token/
#     Path) -> HTTP 400 "0xA011000F: Provider type parameters are not
#     allowed for remote PAM providers." This matches the seeded real
#     "OpenBao-PAM" provider in this lab (GET /PAMProviders/1), which is
#     Remote:true and carries ONLY InstanceLevel=true param values
#     (Secret/Key, populated per cert-store usage) -- it has NO Host/Token/
#     Path values at all. For remote=true providers those non-instance
#     params are apparently expected to be configured locally on the
#     orchestrator, not pushed from Command.
#   - remote=false + the same 3 non-instance-level params -> HTTP 200.
# So this demo models the "Command-hosted" PAM provider shape (remote=
# false), which is the shape that actually accepts provider_type
# parameters end-to-end through this resource's schema.
# ---------------------------------------------------------------------------
data "keyfactor_pam_provider_type" "vault" {
  identifier = "Hashicorp-Vault"
}

resource "keyfactor_pam_provider" "demo" {
  name             = "PamProviderDemo${var.suffix}"
  provider_type_id = data.keyfactor_pam_provider_type.vault.id
  remote           = false

  param_values = [
    {
      param_id = data.keyfactor_pam_provider_type.vault.parameters[0].id
      name     = data.keyfactor_pam_provider_type.vault.parameters[0].name
      value    = var.vault_host
    },
    {
      param_id = data.keyfactor_pam_provider_type.vault.parameters[1].id
      name     = data.keyfactor_pam_provider_type.vault.parameters[1].name
      value    = var.vault_token # sensitive secret param -- write-only, never read back
    },
    {
      param_id = data.keyfactor_pam_provider_type.vault.parameters[2].id
      name     = data.keyfactor_pam_provider_type.vault.parameters[2].name
      value    = var.vault_path_prefix
    },
  ]
}

# ---------------------------------------------------------------------------
# Data source gap fill: read the provider back and assert it agrees with the
# resource's own state (provider_type_name in particular, since that's
# resolved server-side and not something we declare directly).
# ---------------------------------------------------------------------------
data "keyfactor_pam_provider" "demo" {
  identifier = keyfactor_pam_provider.demo.name

  depends_on = [keyfactor_pam_provider.demo]
}

output "pam_provider_id" {
  description = "Integer ID of the demo PAM provider."
  value       = keyfactor_pam_provider.demo.id
}

output "pam_provider_type_id" {
  description = "GUID of the Hashicorp-Vault PAM provider type."
  value       = data.keyfactor_pam_provider_type.vault.id
}

output "pam_provider_type_name_readback" {
  description = "provider_type_name as read back via data.keyfactor_pam_provider -- should be \"Hashicorp-Vault\"."
  value       = data.keyfactor_pam_provider.demo.provider_type_name
}
