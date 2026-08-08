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
  properties = {
    KubeSecretType = "tls"
  }
}

# ---------------------------------------------------------------------------
# K8SJKS — Java KeyStore secrets
# Variation A: inline password (PasswordIsK8SSecret=false, default)
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
    PasswordIsK8SSecret      = "false"
  }
}

# Companion K8S secret for the JKS buddy store — holds the keystore password.
# PasswordFieldName default is "password", so the secret key must match.
resource "kubernetes_secret" "jks_buddy_pwd" {
  metadata {
    name      = "tf-demo-jks-buddy-pwd"
    namespace = local.namespace
  }
  data = {
    password = var.keystore_password
  }
}

# K8SJKS — Variation B: password stored as a companion K8S secret (PasswordIsK8SSecret=true)
# StorePasswordPath points to the K8S secret that holds the keystore password.
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
    PasswordIsK8SSecret      = "true"
    StorePasswordPath        = "${local.namespace}/tf-demo-jks-buddy-pwd"
  }
}

# ---------------------------------------------------------------------------
# K8SPKCS12 — PKCS12 secrets
# Variation A: inline password (PasswordIsK8SSecret=false, default)
# CertificateDataFieldName is required by Command (default ".p12" must be explicit).
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
    PasswordIsK8SSecret      = "false"
  }
}

# Companion K8S secret for the PKCS12 buddy store — holds the keystore password.
resource "kubernetes_secret" "pkcs12_buddy_pwd" {
  metadata {
    name      = "tf-demo-pkcs12-buddy-pwd"
    namespace = local.namespace
  }
  data = {
    password = var.keystore_password
  }
}

# K8SPKCS12 — Variation B: password stored as a companion K8S secret (PasswordIsK8SSecret=true)
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
    PasswordIsK8SSecret      = "true"
    StorePasswordPath        = "${local.namespace}/tf-demo-pkcs12-buddy-pwd"
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
