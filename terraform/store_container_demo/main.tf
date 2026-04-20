terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = "~> 2.0"
    }
  }
}

provider "keyfactor" {}

# ---------------------------------------------------------------------------
# Discover the first approved K8S-capable orchestrator agent.
# ---------------------------------------------------------------------------
data "keyfactor_agents" "k8s" {
  status_filter     = 2             # Approved only
  capability_filter = "K8STLSSecr"  # Any agent with K8S TLS capability
}
