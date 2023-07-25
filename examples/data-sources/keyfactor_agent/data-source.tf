data "keyfactor_agent" "agent_lookup_guid" {
  agent_identifier = "4a1b2631-dff5-4391-a156-96dcba9ea366"
}

data "keyfactor_agent" "agent_lookup_client_machine" {
  agent_identifier = "pam_demouo-10-2"
}