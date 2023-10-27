provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

resource "keyfactor_certificate_store" "k8scluster_w_container" {
  client_machine   = "my-k8s-host"    # ClientMachine
  store_path       = "test-cluster01" # Varies based on store type
  agent_identifier = "my-orch-10-2"   # Orchestrator GUID or Orchestrator ClientMachine name
  store_type       = "K8SCluster"     # Store type, must exist in KeyFactor Command
  properties = {
    # This block will vary based on certificate store type
    IsRootStore = false
  }
  inventory_schedule = "1d"                    # How often to update the inventory
  container_name     = "K8S Clusters"          # Must exist in KeyFactor Command
  server_username    = "kubeconfig"            # Optional, only required if store type requires it.
  server_password    = file("kubeconfig.json") # Optional, only required if store type requires it.
  server_use_ssl     = true                    # Optional, only required if store type requires it.
  store_password     = "password"              # Optional, only required if store type requires it.
}


