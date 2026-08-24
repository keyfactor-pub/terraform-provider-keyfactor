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
#   K8STLSSecr  — alias is the backing secret's name. The k8s-orchestrator extension
#                 requires overwrite=true whenever the backing secret already holds
#                 data (i.e. on every redeploy after the first) and, per Command's own
#                 validation, overwrite=true requires an alias that Command already
#                 tracks in the store's inventory. This demo sets both explicitly so
#                 repeated applies stay idempotent.
#   K8SSecret   — same as K8STLSSecr.
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
  # K8STLSSecr: alias is the K8S secret name; Command already tracks "tf-demo-tls-secret"
  # as the store's inventoried alias, so overwrite=true is required (and valid) to
  # redeploy onto the existing backing secret.
  certificate_alias = "tf-demo-tls-secret"
  overwrite         = true
  #
  # Full inventory-based verification (the default apply behavior): the resource waits
  # for the deployed certificate to appear in the store's inventory before completing.
  # This previously required a workaround because the k8s-orchestrator extension's
  # Management (Add) job silently failed to write the K8s Secret while still reporting
  # Result: Success. Fixed upstream:
  # https://github.com/Keyfactor/k8s-orchestrator/issues/91
}

resource "keyfactor_certificate_deployment" "opaque_secret" {
  certificate_id       = keyfactor_certificate.demo.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_opaque_secret.id
  # K8SSecret: same pattern as tls_secret above.
  certificate_alias = "tf-demo-opaque-secret"
  overwrite         = true
  #
  # Full inventory-based verification (the default apply behavior) — see the tls_secret
  # resource above; same fixed upstream issue applied to K8SSecret as well.
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
