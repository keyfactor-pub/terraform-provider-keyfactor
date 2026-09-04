terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "~> 2.9"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }
}

provider "keyfactor" {}
provider "tls" {}

# ---------------------------------------------------------------------------
# release_validation_demo — trimmed release-smoke test.
#
# A compact end-to-end pass across the provider's most commonly used
# surfaces in one apply: agent lookup, PFX + CSR certificate enrollment, all
# 6 non-buddy K8S store types, and 4 certificate deployments. Intended as a
# fast release-gate check, distinct from the deeper per-feature demos
# elsewhere in terraform/ (k8s_orchestrator_demo covers the buddy-password
# JKS/PKCS12 variants and K8SCert; this demo deliberately does not).
# ---------------------------------------------------------------------------
data "keyfactor_agent" "k8s" {
  agent_identifier = var.agent_identifier
}

locals {
  tmpl           = var.certificate_template != "" ? var.certificate_template : null
  pattern        = var.certificate_enrollment_pattern != "" ? var.certificate_enrollment_pattern : null
  client_machine = "k8s-orchestrator-tf-release"
  # kfclab auth note: in-cluster pod-identity ("Option 3") -- no server_password
  # needed when server_username="kubeconfig". See k8s_orchestrator_demo/stores.tf.
  kubeconfig = var.k8s_server_password_file != "" ? file(var.k8s_server_password_file) : null

  # var.suffix defaults to "_TF" for non-DNS resource naming, but an
  # underscore embedded in a certificate common name makes this lab's
  # EJBCA/OpenBao backend reject enrollment with a generic "invalid custom
  # extension or certificate policy OIDs" error (confirmed 2026-08-08 --
  # CA-side hostname/RFC policy enforcement, not a provider bug). dns_suffix
  # swaps underscores for hyphens so hostnames stay DNS-valid.
  dns_suffix = replace(var.suffix, "_", "-")
}

# ---------------------------------------------------------------------------
# Certificates: 1 PFX + 1 CSR
# ---------------------------------------------------------------------------
resource "keyfactor_certificate" "pfx" {
  common_name                    = "tf-release-pfx${local.dns_suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password
  use_cn_as_friendly_name        = var.use_cn_as_friendly_name
}

resource "tls_private_key" "csr" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "csr" {
  private_key_pem = tls_private_key.csr.private_key_pem
  subject {
    common_name = "tf-release-csr${local.dns_suffix}.example.com"
  }
}

resource "keyfactor_certificate" "csr" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.csr.cert_request_pem
}

# ---------------------------------------------------------------------------
# K8S certificate stores (6 of the 7 K8S-family types; K8SCert and the
# buddy-password JKS/PKCS12 variants are covered separately in
# k8s_orchestrator_demo, not duplicated here)
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_tls_secret" {
  client_machine     = local.client_machine
  store_path         = "${var.namespace}/tf-release-tls-secret"
  agent_identifier   = data.keyfactor_agent.k8s.agent_id
  store_type         = "K8STLSSecr"
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
  properties = {
    KubeSecretType = "tls"
  }
}

resource "keyfactor_certificate_store" "k8s_opaque_secret" {
  client_machine     = local.client_machine
  store_path         = "${var.namespace}/tf-release-opaque-secret"
  agent_identifier   = data.keyfactor_agent.k8s.agent_id
  store_type         = "K8SSecret"
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
  properties = {
    KubeSecretType = "opaque"
  }
}

# PasswordIsK8SSecret is deliberately NOT set below (even as "false"). This
# lab's k8s-orchestrator extension version does not define that property at
# all on K8SJKS/K8SPKCS12 (GET /CertificateStoreTypes/107, /108, confirmed
# 2026-08-07) -- Command rejected it outright with "The Certificate Store
# Property, 'PasswordIsK8SSecret', is not a valid property for Certificate
# Store Type: '107'" (same for '108'). See k8s_orchestrator_demo/stores.tf
# for the same fix and the companion-K8S-secret ("buddy") variant, which
# this trimmed release-gate demo does not cover.
resource "keyfactor_certificate_store" "k8s_jks" {
  client_machine     = local.client_machine
  store_path         = "${var.namespace}/tf-release-jks"
  agent_identifier   = data.keyfactor_agent.k8s.agent_id
  store_type         = "K8SJKS"
  store_password     = var.keystore_password
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
  properties = {
    KubeSecretType           = "jks"
    CertificateDataFieldName = "jks"
  }
}

resource "keyfactor_certificate_store" "k8s_pkcs12" {
  client_machine     = local.client_machine
  store_path         = "${var.namespace}/tf-release-pkcs12"
  agent_identifier   = data.keyfactor_agent.k8s.agent_id
  store_type         = "K8SPKCS12"
  store_password     = var.keystore_password
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
  properties = {
    KubeSecretType           = "pkcs12"
    CertificateDataFieldName = ".p12"
  }
}

resource "keyfactor_certificate_store" "k8s_ns" {
  client_machine     = local.client_machine
  store_path         = var.namespace
  agent_identifier   = data.keyfactor_agent.k8s.agent_id
  store_type         = "K8SNS"
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
}

resource "keyfactor_certificate_store" "k8s_cluster" {
  client_machine     = local.client_machine
  store_path         = "/"
  agent_identifier   = data.keyfactor_agent.k8s.agent_id
  store_type         = "K8SCluster"
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
}

# ---------------------------------------------------------------------------
# Deployments — one per deployable store type (K8SNS/K8SCluster are
# discovery-only, not deployment targets)
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_deployment" "tls_secret" {
  certificate_id       = keyfactor_certificate.pfx.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_tls_secret.id
}

resource "keyfactor_certificate_deployment" "opaque_secret" {
  certificate_id       = keyfactor_certificate.pfx.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_opaque_secret.id
}

resource "keyfactor_certificate_deployment" "jks" {
  certificate_id       = keyfactor_certificate.pfx.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_jks.id
  certificate_alias    = "jks/tf-release"
}

resource "keyfactor_certificate_deployment" "pkcs12" {
  certificate_id       = keyfactor_certificate.pfx.certificate_id
  certificate_store_id = keyfactor_certificate_store.k8s_pkcs12.id
  certificate_alias    = ".p12/tf-release"
}
