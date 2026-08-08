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
# keyfactor_certificate_authority — HTTPS/AnyCA REST Gateway (ca_type=1) demo
# exercising the OAuth connector fields (client_id/client_secret/token_url/
# scope/audience) through a full create + update lifecycle.
#
# This registers a SEPARATE CA connection record pointed at the same gateway
# host as the lab's existing "OpenBao PKI" CA (id 2) -- it does NOT touch or
# duplicate that CA's actual configuration, it just proves the OAuth
# connector fields round-trip correctly on create/update against a real
# AnyCA REST Gateway endpoint. Real, working OAuth client credentials for
# that gateway MUST be supplied via TF_VAR_ca_client_id /
# TF_VAR_ca_client_secret / TF_VAR_ca_token_url (no defaults -- see
# variables.tf; never commit real values here).
#
# force_save=true is used the same way ca_schedule_demo uses it: several
# HTTPS-CA fields (audience/scope/client_secret rotation) are exercised via
# `-var` between apply steps to prove Update() handles them, modeled on the
# archived state snapshot for this demo (ADO/HANDOFF history), which showed
# client_id/audience/scope all changing between an initial create and a
# follow-up update.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_authority" "demo" {
  logical_name = "tf-demo-ejbca-ca${var.suffix}"
  host_name    = var.host_name
  ca_type      = 1 # HTTPS / AnyCA REST Gateway
  force_save   = var.force_save

  configuration_tenant                = "ejbca"
  forest_root                         = "ejbca"
  standalone                          = false
  monitor_thresholds                  = var.monitor_thresholds
  new_end_entity_on_renew_and_reissue = true

  allowed_enrollment_types          = 3
  issuance_min                      = var.issuance_min
  issuance_max                      = var.issuance_max
  failure_max                       = var.failure_max
  full_scan_interval_minutes        = var.full_scan_interval_minutes
  incremental_scan_interval_minutes = var.incremental_scan_interval_minutes
  threshold_check_interval_minutes  = var.threshold_check_interval_minutes

  key_retention      = var.key_retention
  key_retention_days = var.key_retention_days

  # OAuth connector fields -- the actual point of this demo.
  client_id     = var.ca_client_id
  client_secret = var.ca_client_secret
  token_url     = var.ca_token_url
  scope         = var.ca_scope
  audience      = var.ca_audience
}

# ---------------------------------------------------------------------------
# Data source gap fill: read the CA back and assert it agrees with the
# resource's own state.
# ---------------------------------------------------------------------------
data "keyfactor_certificate_authority" "demo" {
  identifier = keyfactor_certificate_authority.demo.logical_name

  depends_on = [keyfactor_certificate_authority.demo]
}

output "ca_id" {
  description = "ID of the demo EJBCA/AnyCA HTTPS certificate authority record."
  value       = keyfactor_certificate_authority.demo.id
}

output "datasource_readback_matches" {
  description = "True if the data source's view of the CA agrees with the resource's own state."
  value       = data.keyfactor_certificate_authority.demo.id == keyfactor_certificate_authority.demo.id
}

output "logical_name" {
  description = "Logical name of the demo CA record."
  value       = keyfactor_certificate_authority.demo.logical_name
}

output "audience" {
  description = "audience as read back into Terraform state."
  value       = keyfactor_certificate_authority.demo.audience
}

output "scope" {
  description = "scope as read back into Terraform state."
  value       = keyfactor_certificate_authority.demo.scope
}
