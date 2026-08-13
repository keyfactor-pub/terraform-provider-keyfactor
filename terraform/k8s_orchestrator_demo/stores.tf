# ---------------------------------------------------------------------------
# Discover the first approved K8S-capable orchestrator agent.
# ---------------------------------------------------------------------------
data "keyfactor_agents" "k8s" {
  status_filter     = 2            # Approved only
  capability_filter = "K8STLSSecr" # Any agent with K8S capability
}

# ---------------------------------------------------------------------------
# kfclab auth note: the lab's k8s-orchestrator UOs run in-cluster with a
# ServiceAccount/ClusterRole/ClusterRoleBinding (the "k8s-orch-rbac" deploy
# step) and use in-cluster pod-identity auth for Command's K8S store types
# ("Option 3" per the k8s-orchestrator docs): server_username = "kubeconfig"
# with NO server_password at all. This matches kfclab's own seeding (see
# cert_stores: in kfclab's examples/full/kfclab.yaml) and needs no kubeconfig
# JSON file. Set var.k8s_server_password_file only for labs/orchestrators
# that are NOT configured for in-cluster pod identity and need an explicit
# flat kubeconfig JSON as the store password instead.
# ---------------------------------------------------------------------------
locals {
  agent_id       = data.keyfactor_agents.k8s.agents[0].agent_id
  client_machine = "k8s-orchestrator-tf-demo"
  namespace      = var.namespace
  kubeconfig     = var.k8s_server_password_file != "" ? file(var.k8s_server_password_file) : null
}

# ---------------------------------------------------------------------------
# inventory_schedule caveat:
# "immediate" is a one-shot trigger — Command removes the schedule once the
# inventory job completes (or exhausts retries).  The next terraform plan
# will show drift from "immediate" → empty/daily.  To avoid perpetual drift
# after the first apply, set var.inventory_schedule = "Daily at HH:MM:SS".
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# K8STLSSecr — TLS secrets (certificate + private key in a tls-type secret)
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_tls_secret" {
  client_machine     = local.client_machine
  store_path         = "${local.namespace}/tf-demo-tls-secret"
  agent_identifier   = local.agent_id
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

# ---------------------------------------------------------------------------
# K8SSecret — Opaque secrets (PEM cert/key stored in opaque K8S secret)
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_opaque_secret" {
  client_machine     = local.client_machine
  store_path         = "${local.namespace}/tf-demo-opaque-secret"
  agent_identifier   = local.agent_id
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

# ---------------------------------------------------------------------------
# K8SCert — Certificate-only secrets (public cert, no private key)
#
# K8SCert's actual property set (GET /CertificateStoreTypes/102, confirmed
# 2026-08-07) is ServerUsername/ServerPassword/ServerUseSsl/KubeSecretName --
# there is NO KubeSecretType property on this store type (Command rejected it
# with "The Certificate Store Property, 'KubeSecretType', is not a valid
# property for Certificate Store Type: '102'"). This also matches
# SupportedOperations for 102 (Add/Create/Enrollment/Remove all false,
# Discovery only) -- K8SCert is a discovery-only store, hence no deployment
# resource targets it in deployments.tf.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_cert" {
  client_machine     = local.client_machine
  store_path         = "${local.namespace}/tf-demo-cert"
  agent_identifier   = local.agent_id
  store_type         = "K8SCert"
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = false # K8SCert has no Create management job; override to false
}

# ---------------------------------------------------------------------------
# K8SJKS — Java KeyStore secrets
#
# PasswordIsK8SSecret/StorePasswordPath are DELIBERATELY NOT SET below.
# This lab's k8s-orchestrator extension version does not define either
# property on K8SJKS/K8SPKCS12 at all (GET /CertificateStoreTypes/107 and
# /108, confirmed 2026-08-07) -- Command rejected them outright with "The
# Certificate Store Property, 'PasswordIsK8SSecret', is not a valid property
# for Certificate Store Type: '107'" (same for '108'), even when set to
# "false". So the "buddy" companion-K8S-secret password variant (Variation
# B) cannot be wired into Command's store config on this lab version; both
# variants below use inline store_password instead.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_jks" {
  client_machine     = local.client_machine
  store_path         = "${local.namespace}/tf-demo-jks"
  agent_identifier   = local.agent_id
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

# Companion K8S secret -- created to exercise the kubernetes_secret resource
# and kubeconfig-based auth (~/.kube/kfc-lab.yaml via var.k8s_credentials_file),
# but NOT actually consumed by keyfactor_certificate_store.k8s_jks_buddy below:
# this lab's K8SJKS store type has no StorePasswordPath property to point at
# it (see header comment above). PasswordFieldName default is "password", so
# the secret key still matches what a lab WITH that property would expect.
resource "kubernetes_secret" "jks_buddy_pwd" {
  metadata {
    name      = "tf-demo-jks-buddy-pwd"
    namespace = local.namespace
  }
  data = {
    password = var.keystore_password
  }
}

# K8SJKS — "buddy" store at a distinct path. See header comment: this lab's
# K8SJKS store type does not support PasswordIsK8SSecret/StorePasswordPath,
# so this uses the same inline-password config as k8s_jks above rather than
# actually referencing kubernetes_secret.jks_buddy_pwd.
resource "keyfactor_certificate_store" "k8s_jks_buddy" {
  depends_on         = [kubernetes_secret.jks_buddy_pwd]
  client_machine     = local.client_machine
  store_path         = "${local.namespace}/tf-demo-jks-buddy"
  agent_identifier   = local.agent_id
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

# ---------------------------------------------------------------------------
# K8SPKCS12 — PKCS12 secrets
# CertificateDataFieldName is required by Command (default ".p12" must be explicit).
# PasswordIsK8SSecret/StorePasswordPath omitted for the same reason as K8SJKS above.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_pkcs12" {
  client_machine     = local.client_machine
  store_path         = "${local.namespace}/tf-demo-pkcs12"
  agent_identifier   = local.agent_id
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

# Companion K8S secret -- see jks_buddy_pwd comment above; same caveat applies.
resource "kubernetes_secret" "pkcs12_buddy_pwd" {
  metadata {
    name      = "tf-demo-pkcs12-buddy-pwd"
    namespace = local.namespace
  }
  data = {
    password = var.keystore_password
  }
}

# K8SPKCS12 — "buddy" store at a distinct path; see k8s_jks_buddy comment above.
resource "keyfactor_certificate_store" "k8s_pkcs12_buddy" {
  depends_on         = [kubernetes_secret.pkcs12_buddy_pwd]
  client_machine     = local.client_machine
  store_path         = "${local.namespace}/tf-demo-pkcs12-buddy"
  agent_identifier   = local.agent_id
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

# ---------------------------------------------------------------------------
# K8SNS — Namespace-scoped store (discovers all secrets in a namespace)
# No KubeSecretType property — not supported by this store type.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_ns" {
  client_machine     = local.client_machine
  store_path         = local.namespace
  agent_identifier   = local.agent_id
  store_type         = "K8SNS"
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
}

# ---------------------------------------------------------------------------
# K8SCluster — Cluster-wide store (discovers all secrets across all namespaces)
# No KubeSecretType property — not supported by this store type.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "k8s_cluster" {
  client_machine     = local.client_machine
  store_path         = "/"
  agent_identifier   = local.agent_id
  store_type         = "K8SCluster"
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
}
