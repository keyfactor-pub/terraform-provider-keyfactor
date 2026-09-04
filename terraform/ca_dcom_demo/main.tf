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
# keyfactor_certificate_authority : DCOM (ca_type=0) record-only demo.
#
# This is a RECORD-ONLY registration for a fictitious Windows/DCOM CA -- it
# never points at a real, reachable AD CS server. The provider itself does
# not validate DCOM connectivity for host_name/forest_root/configuration_tenant
# on Create/Update in the same way HTTPS (ca_type=1) CAs get network-probed;
# it primarily records the connection so Command can associate certificates
# and (if the host were real and reachable) run scans against it.
#
# kfclab is an Authentik-OAuth-only lab with no Active Directory / DCOM CA
# backend at all (see terraform/security_identity_demo for the analogous AD
# constraint on keyfactor_identity). This demo therefore:
#   - uses fabricated, clearly-fake AD host/tenant values (never a real
#     lab hostname)
#   - is expected to either (a) succeed as a pure metadata record with no
#     live connectivity check, matching pre-migration lab behavior, or
#     (b) be rejected outright by this Command instance if it validates
#     DCOM CA records more strictly than the previous lab did
#   - the GNUmakefile's `lifecycle` target treats a Create failure here as
#     a clean, reported SKIP (not a harness-wide failure) so this demo
#     documents the constraint rather than masking it
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_authority" "demo" {
  logical_name = "tf-demo-dcom-ca${var.suffix}"
  host_name    = var.host_name
  ca_type      = 0 # DCOM

  forest_root              = var.forest_root
  configuration_tenant     = var.forest_root
  standalone               = false
  monitor_thresholds       = false
  allowed_enrollment_types = 0
}

output "ca_id" {
  description = "ID of the demo DCOM certificate authority record."
  value       = keyfactor_certificate_authority.demo.id
}

output "logical_name" {
  description = "Logical name of the demo DCOM certificate authority record."
  value       = keyfactor_certificate_authority.demo.logical_name
}
