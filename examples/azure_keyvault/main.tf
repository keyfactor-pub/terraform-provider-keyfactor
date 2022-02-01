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

resource "keyfactor_store" "AKV1" {
  provider = keyfactor.command
  store {
    client_machine  = "akv_demo"
    store_path      = "https://companykeyvault.vault.azure.net/"
    agent_id = "keyfactorOrchestratorAgentID"
    cert_store_type = 106
    property {
      name  = "TenantID"
      value = var.az_tenant_id
    }
    property {
      name  = "ResourceGroupName"
      value = var.az_resource_group_name
    }
    property {
      name  = "ApplicationId"
      value = var.az_application_id
    }
    property {
      name  = "ClientSecret"
      value = var.az_client_secret
    }
    property {
      name  = "SubscriptionId"
      value = var.az_subscription_id
    }
    property {
      name  = "APIObjectId"
      value = var.az_app_object_id
    }
    property {
      name  = "VaultName"
      value = var.az_vault_name
    }
    inventory_schedule {
      interval {
        minutes = 60
      }
    }
  }
}

output "store" {
  value = keyfactor_store.AKV1.store[0]
}


resource "keyfactor_certificate" "PFXCertificate" {
  provider = keyfactor.command
  certificate {
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
      name  = "Department"
      value = "Engineering"
    }
    metadata {
      name  = "Email-Contact"
      value = "admin@example.com"
    }
    key_password          = "P@s5w0Rd2321!"
    certificate_authority = "keyfactor.example.com\\CA 1"
    cert_template         = "WebServer1yr"

    deployment {
      store_ids      = [keyfactor_store.AKV1.store[0].keyfactor_id]
      store_type_ids = [keyfactor_store.AKV1.store[0].cert_store_type]
      alias          = ["terraform"]
    }
  }
}

output "pfxCertificate" {
  value = keyfactor_certificate.PFXCertificate.certificate[0]
}
