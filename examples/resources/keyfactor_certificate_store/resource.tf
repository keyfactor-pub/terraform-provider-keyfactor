resource "keyfactor_certificate_store" "example" {
  client_machine   = "my-k8s-host"
  store_path       = "default/my-tls-secret"
  agent_identifier = "my-orch-10-2"
  store_type       = "K8STLSSecr"
  properties = {
    KubeSecretType = "tls"
  }
  inventory_schedule = "Daily at 08:00:00"
  server_username    = "kubeconfig"
  server_password    = file("kubeconfig.json")
  server_use_ssl     = true
}
