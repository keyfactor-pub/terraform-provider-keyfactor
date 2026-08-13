# ---------------------------------------------------------------------------
# Certificate enrollment
# ---------------------------------------------------------------------------
locals {
  tmpl    = var.certificate_template != "" ? var.certificate_template : null
  pattern = var.certificate_enrollment_pattern != "" ? var.certificate_enrollment_pattern : null
}

resource "keyfactor_certificate" "demo" {
  common_name                    = "tf-k8s-demo.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password
  use_cn_as_friendly_name        = var.use_cn_as_friendly_name
}

# ---------------------------------------------------------------------------
# Deploy to all stores that support add-certificate operations.
#
# K8SNS and K8SCluster are discovery/inventory stores only — they discover
# existing secrets across a namespace or the whole cluster but do not serve
# as deployment targets.
#
# K8SCert manages Kubernetes CSR objects (certificates.k8s.io/v1) which are
# read-only — the Add operation is not supported by this store type.
#
# Alias format per store type (from k8s-orchestrator docs):
#   K8STLSSecr  — omit alias; cert is placed into the store's backing TLS
#                 secret unconditionally. Providing an alias requires overwrite=true
#                 AND the alias must already be tracked by Command.
#   K8SSecret   — same as K8STLSSecr; omit alias for unconditional placement.
#   K8SJKS      — "<CertificateDataFieldName>/<keystore-alias>"
#                 CertificateDataFieldName defaults to "jks" when not set.
#                 Example: "jks/my-cert"
#   K8SPKCS12   — "<CertificateDataFieldName>/<keystore-alias>"
#                 CertificateDataFieldName defaults to ".p12" when not set.
#                 Example: ".p12/my-cert"
# ---------------------------------------------------------------------------

resource "keyfactor_certificate_deployment" "tls_secret" {
  certificate_id       = keyfactor_certificate.demo.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_tls_secret.id
  # K8STLSSecr: alias is the K8S secret name; omitting alias lets Command match by cert ID.
  # Overwrite is required if an alias is provided but the alias already exists; without
  # an alias the cert is placed into the store's backing secret unconditionally.

  # TEMPORARY WORKAROUND — DO NOT treat as the intended long-term config.
  # The k8s-orchestrator extension's Management (Add) job for K8STLSSecr, on the
  # no-alias/"unconditional replace" code path used here, reports Result: Success
  # in Command's JobHistory but does not actually write the new certificate into
  # the target K8s Secret (confirmed against a live lab: JobHistory showed
  # Success while the Secret's tls.crt still held a certificate enrolled 5 days
  # earlier). Because the job falsely reports success, fail_on_job_failure cannot
  # catch this — it only fires on a genuine failure/warning result. The only way
  # to avoid an indefinite hang polling for inventory that will never reflect the
  # new cert is to skip inventory validation entirely.
  # skip_inventory_validation = true therefore means "fire and forget": apply
  # goes green once the job is submitted (and even falsely reports success), but
  # this does NOT confirm the certificate actually landed in the K8s Secret.
  # Tracked upstream: https://github.com/Keyfactor/k8s-orchestrator/issues/91
  # REVERT: remove this line once the upstream issue is fixed, to restore full
  # inventory-based verification (the demo's actual intended behavior).
  skip_inventory_validation = true
}

resource "keyfactor_certificate_deployment" "opaque_secret" {
  certificate_id       = keyfactor_certificate.demo.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_opaque_secret.id
  # K8SSecret: same pattern as K8STLSSecr — alias optional, omit for unconditional placement.

  # TEMPORARY WORKAROUND — DO NOT treat as the intended long-term config.
  # Same root cause as tls_secret above: the k8s-orchestrator extension's
  # Management (Add) job for K8SSecret, on the no-alias/"unconditional replace"
  # code path, reports Result: Success in Command's JobHistory but does not
  # actually write the new certificate into the target K8s Secret (confirmed
  # against a live lab via JobHistory + direct inspection of the Secret's
  # contents). fail_on_job_failure cannot catch this false-positive success, so
  # skip_inventory_validation = true is used to avoid an indefinite hang.
  # skip_inventory_validation = true means "fire and forget": apply goes green
  # once the job is submitted (and even falsely reports success), but this does
  # NOT confirm the certificate actually landed in the K8s Secret.
  # Tracked upstream: https://github.com/Keyfactor/k8s-orchestrator/issues/91
  # REVERT: remove this line once the upstream issue is fixed, to restore full
  # inventory-based verification (the demo's actual intended behavior).
  skip_inventory_validation = true
}

resource "keyfactor_certificate_deployment" "jks" {
  certificate_id       = keyfactor_certificate.demo.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_jks.id
  certificate_alias    = "jks/tf-k8s-demo"
}

resource "keyfactor_certificate_deployment" "jks_buddy" {
  certificate_id       = keyfactor_certificate.demo.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_jks_buddy.id
  certificate_alias    = "jks/tf-k8s-demo"
}

resource "keyfactor_certificate_deployment" "pkcs12" {
  certificate_id       = keyfactor_certificate.demo.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_pkcs12.id
  certificate_alias    = ".p12/tf-k8s-demo"
}

resource "keyfactor_certificate_deployment" "pkcs12_buddy" {
  certificate_id       = keyfactor_certificate.demo.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_pkcs12_buddy.id
  certificate_alias    = ".p12/tf-k8s-demo"
}
