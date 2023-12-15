provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_agent" "agent_from_guid" {
  agent_identifier = "00000000-0000-0000-0000-000000000000" # Lookup by agent GUID
}

data "keyfactor_agent" "agent_from_client_machine_name" {
  agent_identifier = "my_client_machine" # Lookup by client machine name
}

