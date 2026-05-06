provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

# Both client_machine and store_path are required to do a lookup
data "keyfactor_certificate_store" "k8s_cluster_store_lookup" {
  client_machine = "192.168.0.4"
  store_path     = "/home/azureuser/certs"
}

# The application_name (or container_name for pre-v25 compatibility) is available on the result:
# data.keyfactor_certificate_store.k8s_cluster_store_lookup.application_name
