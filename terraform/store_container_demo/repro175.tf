# ---------------------------------------------------------------------------
# Issue #175 reproduction: keyfactor_certificate_store Update() silently
# clears a container/application assignment that was made OUT-OF-BAND
# (portal, or a direct API call) whenever Terraform's config never declares
# application_name/container_name for that store.
#
# See HANDOFF_container_clearing_bug.md (repo root, not committed) for the
# full root-cause writeup. Summary of the confirmed root cause:
#   - lookupContainerNameByID (keyfactor/helpers.go) silently swallows any
#     error from GetStoreContainer() and falls back to an empty hint, which
#     nulls container_name/application_name in state on the very first
#     post-assignment Read().
#   - resourceCertificateStore.Update() (resource_keyfactor_certificate_store.go)
#     then resolves containerId to 0 from that null name and OMITS the
#     ContainerId field entirely from the PUT payload (intToPointer(0) ==
#     nil, and the SDK field is `omitempty`) -- Command interprets an
#     omitted ContainerId as "clear the assignment."
#
# This resource intentionally NEVER declares application_name/container_name
# -- that omission is the whole point of the repro. The GNUmakefile's
# repro175-* targets drive the actual reproduction sequence:
#   1. repro175-apply       -- create the store with no container assignment
#   2. repro175-seed        -- out-of-band: assign it to the application
#                               created in application.tf via a direct
#                               PUT /CertificateStores/{id} call (bypassing
#                               Terraform entirely)
#   3. repro175-verify-plan -- plan should show no config-level change to
#                               container_name/application_name (Terraform
#                               never declared them, so this alone proves
#                               nothing yet)
#   4. repro175-verify-apply -- apply an UNRELATED attribute change
#                               (repro175_inventory_schedule). Pre-fix, this
#                               is where Update() clears the assignment and
#                               Terraform fails with "Provider produced
#                               inconsistent result after apply:
#                               .container_id: was cty.NumberIntVal(N), but
#                               now cty.NumberIntVal(0)". Post-fix, apply
#                               must succeed AND the assignment must survive.
#   5. repro175-verify-server -- direct API GET confirming ContainerId is
#                               still the real, non-zero value server-side.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "repro175" {
  depends_on = [keyfactor_application.demo]

  client_machine   = local.client_machine
  store_path       = "${var.namespace}/tf-repro175"
  agent_identifier = local.agent_id
  store_type       = "K8STLSSecr"
  server_username  = "kubeconfig"
  server_password  = local.kubeconfig
  server_use_ssl   = true

  # NOTE: application_name / container_name are deliberately ABSENT here --
  # not just null-valued, fully omitted from the resource body -- to
  # reproduce issue #175. The out-of-band assignment happens via
  # repro175-seed (direct API call), never through this config.

  inventory_schedule = var.repro175_inventory_schedule
  create_if_missing  = var.create_if_missing
  properties = {
    KubeSecretType = "tls"
  }
}

output "repro175_store_id" {
  description = "ID of the issue #175 repro store."
  value       = keyfactor_certificate_store.repro175.id
}

output "repro175_container_id" {
  description = "container_id currently in Terraform state for the repro175 store. Must stay non-zero across repro175-verify-apply for the fix to be confirmed."
  value       = keyfactor_certificate_store.repro175.container_id
}
