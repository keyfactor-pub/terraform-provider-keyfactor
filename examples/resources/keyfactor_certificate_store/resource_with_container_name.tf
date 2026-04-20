# Pre-v25 style: use container_name to associate the store with an application/container.
# Functionally equivalent to application_name — both attributes are supported.
resource "keyfactor_certificate_store" "legacy_container" {
  client_machine   = "my-k8s-host"
  store_path       = "default/my-legacy-secret"
  agent_identifier = "my-orch-10-2"
  store_type       = "K8STLSSecr"
  properties = {
    KubeSecretType = "tls"
  }
  inventory_schedule = "Daily at 08:00:00"
  container_name     = "K8S Clusters"
  server_username    = "kubeconfig"
  server_password    = file("kubeconfig.json")
  server_use_ssl     = true
}
