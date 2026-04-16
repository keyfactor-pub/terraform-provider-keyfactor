# Look up an existing application (container) by name to reference its name
# in the certificate store resource. This avoids hard-coding the application
# name and makes the configuration more reusable.
data "keyfactor_application" "k8s_clusters" {
  identifier = "K8S Clusters"
}

resource "keyfactor_certificate_store" "k8s_store" {
  client_machine   = "my-k8s-host"
  store_path       = "default/my-tls-secret"
  agent_identifier = "my-orch-10-2"
  store_type       = "K8STLSSecr"
  properties = {
    KubeSecretType = "tls"
  }
  inventory_schedule = "Daily at 08:00:00"
  application_name   = data.keyfactor_application.k8s_clusters.name
  server_username    = "kubeconfig"
  server_password    = file("kubeconfig.json")
  server_use_ssl     = true
}
