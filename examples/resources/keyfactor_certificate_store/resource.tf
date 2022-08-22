provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

resource "keyfactor_certificate_store" "iis_trusted_roots" {
  client_machine = "myorchestrator01"                     # Orchestrator client name
  store_path     = "IIS Trusted Roots"                    # Varies based on store type
  agent_id       = "c2b2084f-3d89-4ded-bb8b-b4e0e74d2b59" # Orchestrator GUID
  store_type     = "IIS"                                  # Must exist in KeyFactor
  properties     = {
    # Optional properties based on the store type
    UseSSL = true
  }
  inventory_schedule = "60m"                # How often to update the inventory
  container_id       = 2                    # ID of the KeyFactor container
  password           = "my store password!"
  # The password for the certificate store. Note: This is bad practice, use TF_VAR_<variable_name> instead.
}