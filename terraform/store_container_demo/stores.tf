# ---------------------------------------------------------------------------
# kfclab auth note: the lab's k8s-orchestrator UOs run in-cluster with
# pod-identity auth ("Option 3" -- server_username="kubeconfig", no
# server_password). See k8s_orchestrator_demo/stores.tf for the full note.
# Set var.k8s_server_password_file only for labs without in-cluster identity.
# ---------------------------------------------------------------------------
locals {
  agent_id       = data.keyfactor_agents.k8s.agents[0].agent_id
  client_machine = "store-container-tf-demo"
  kubeconfig     = var.k8s_server_password_file != "" ? file(var.k8s_server_password_file) : null
}

# ---------------------------------------------------------------------------
# Store A: pre-v25 style : uses container_name to link to the application.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "container_name_style" {
  depends_on = [keyfactor_application.demo]

  client_machine     = local.client_machine
  store_path         = "${var.namespace}/tf-container-name-demo"
  agent_identifier   = local.agent_id
  store_type         = "K8STLSSecr"
  container_name     = keyfactor_application.demo.name
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
# Store B: v25+ style : uses application_name (alias for container_name).
# Both stores are linked to the same application; the two attribute names are
# interchangeable and must NOT force resource replacement when switched.
# ---------------------------------------------------------------------------
resource "keyfactor_certificate_store" "application_name_style" {
  depends_on = [keyfactor_application.demo]

  client_machine     = local.client_machine
  store_path         = "${var.namespace}/tf-application-name-demo"
  agent_identifier   = local.agent_id
  store_type         = "K8STLSSecr"
  application_name   = keyfactor_application.demo.name
  server_username    = "kubeconfig"
  server_password    = local.kubeconfig
  server_use_ssl     = true
  inventory_schedule = var.inventory_schedule
  create_if_missing  = var.create_if_missing
  properties = {
    KubeSecretType = "tls"
  }
}
