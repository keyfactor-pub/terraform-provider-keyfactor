terraform {
  required_providers {
    keyfactor = {
      version = "~> 1.0.1"
      source  = "keyfactor.com/keyfactordev/keyfactor"
    }
  }
}

provider "keyfactor" {
  alias       = "command"
  hostname    = "keyfactor.example.com"
  kf_username = "keyfactorUser"
  kf_password = "P@s5woRd!"
}

// Create Azure Key Vault certificate store
resource "keyfactor_store" "AKV1" {
  provider        = keyfactor.command
  client_machine  = "akv_demo"
  store_path      = "https://companykeyvault.vault.azure.net/"
  agent_id        = "keyfactorOrchestratorAgentID"
  cert_store_type = 106
  properties {
    TenantID          = var.az_tenant_id
    ResourceGroupName = var.az_resource_group_name
    ApplicationId     = var.az_application_id
    ClientSecret      = var.az_client_secret
    SubscriptionId    = var.az_subscription_id
    APIObjectId       = var.az_app_object_id
    VaultName         = var.az_vault_name
  }
  inventory_schedule {
    interval {
      minutes = 60
    }
  }
}

// Enroll a PFX certificate with Keyfactor
resource "keyfactor_certificate" "PFXCertificate" {
  provider = keyfactor.command
  subject {
    subject_common_name         = "terraform"
    subject_organization        = "example"
    subject_locality            = "Springfield"
    subject_country             = "US"
    subject_organizational_unit = "SE"
    subject_state               = "NA"
  }
  sans {
    san_ip4 = ["192.168.123.2", "172.51.2.4"]
    san_uri = ["example.com"]
  }
  metadata {
    Department    = "Engineering"
    Email-Contact = "admin@example.com"
  }
  key_password          = "P@s5w0Rd2321!"
  certificate_authority = "keyfactor.example.com\\CA 1"
  cert_template         = "WebServer1yr"
}

// Deploy new PFX certificate into Azure Key Vault
resource "keyfactor_deploy_certificate" "test" {
  certificate_id = keyfactor_certificate.PFXCertificate.keyfactor_id
  password       = keyfactor_certificate.PFXCertificate.key_password
  store {
    certificate_store_id = keyfactor_store.AKV1.keyfactor_id
    alias                = "deploy1"
  }
}