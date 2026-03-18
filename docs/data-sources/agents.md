---
page_title: "keyfactor_agents Data Source - terraform-provider-keyfactor"
subcategory: ""
description: |-
  Returns a list of orchestrator agents registered in Keyfactor Command. Supports optional filtering by status, client machine name, and capability.
---

# keyfactor_agents (Data Source)

Returns a list of orchestrator agents registered in Keyfactor Command. Supports optional filtering by status, client machine name, and capability.

Use `keyfactor_agent` (singular) to look up a single agent by GUID or machine name. Use `keyfactor_agents` (plural) to list and filter multiple agents.

## Example Usage

### List all agents

```terraform
data "keyfactor_agents" "all" {
}

output "agent_count" {
  value = length(data.keyfactor_agents.all.agents)
}

output "agent_ids" {
  value = [for a in data.keyfactor_agents.all.agents : a.agent_id]
}
```

### Filter by status (approved only)

```terraform
data "keyfactor_agents" "approved" {
  status_filter = 2  # 1 = New, 2 = Approved, 3 = Disapproved
}

output "approved_agents" {
  value = [for a in data.keyfactor_agents.approved.agents : {
    id      = a.agent_id
    machine = a.client_machine
    version = a.version
  }]
}
```

### Filter by client machine name

```terraform
data "keyfactor_agents" "k8s" {
  client_machine_filter = "k8s-node"  # case-insensitive substring match
}
```

### Filter by capability

```terraform
data "keyfactor_agents" "tls" {
  capability_filter = "K8STLSSecr"
}
```

### Use with certificate store resource

```terraform
data "keyfactor_agents" "approved_ssl" {
  status_filter     = 2
  capability_filter = "SSL"
}

resource "keyfactor_certificate_store" "example" {
  agent_id       = data.keyfactor_agents.approved_ssl.agents[0].agent_id
  client_machine = data.keyfactor_agents.approved_ssl.agents[0].client_machine
  # ... other store configuration
}
```

## Schema

### Optional

- `status_filter` (Number) Filter agents by status. 1 = New, 2 = Approved, 3 = Disapproved. If not set, all agents are returned.
- `client_machine_filter` (String) Filter agents by client machine name (case-insensitive substring match).
- `capability_filter` (String) Filter agents to those that report a specific capability (e.g., "K8STLSSecr", "SSL").

### Read-Only

- `id` (String) Placeholder ID for Terraform framework compatibility.
- `agents` (List of Object) List of orchestrator agents matching the filter criteria. Each agent has the following attributes:

### Agent Object Attributes

- `agent_id` (String) The GUID of the orchestrator.
- `agent_platform` (Number) An integer indicating the platform for the orchestrator.
- `auth_certificate_reenrollment` (String) The value of the orchestrator certificate reenrollment request or require status.
- `blueprint` (String) The name of the blueprint associated with the orchestrator.
- `capabilities` (List of String) An array of capabilities reported by the orchestrator.
- `client_machine` (String) The client machine on which the orchestrator is installed.
- `last_error_code` (Number) The last error code reported from the orchestrator when trying to register a session.
- `last_error_message` (String) The last error message reported from the orchestrator when trying to register a session.
- `last_seen` (String) The time, in UTC, at which the orchestrator last contacted Keyfactor Command.
- `last_thumbprint_used` (String) The thumbprint of the certificate that the orchestrator most recently used for authentication.
- `legacy_thumbprint` (String) The thumbprint of the certificate previously used by the orchestrator before a certificate renewal.
- `status` (Number) An integer indicating the orchestrator status. 1 = New, 2 = Approved, 3 = Disapproved.
- `thumbprint` (String) The thumbprint of the certificate used by the orchestrator for client certificate authentication.
- `username` (String) The Active Directory user or service account the orchestrator is using.
- `version` (String) The version of the orchestrator.
