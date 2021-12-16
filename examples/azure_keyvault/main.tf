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
  dev_mode    = true
}

resource "keyfactor_store" "AKS1" {
  provider = keyfactor.command
  store {
    client_machine  = "aks_demo"
    store_path      = "https://companykeyvault.vault.azure.net/"
    cert_store_type = 106
    property {
      name  = "TenantID"
      value = "tenant GUID"
    }
    property {
      name  = "ResourceGroupName"
      value = "production"
    }
    property {
      name  = "ApplicationId"
      value = "appID"
    }
    property {
      name  = "ClientSecret"
      value = "SPSecret"
    }
    property {
      name  = "SubscriptionId"
      value = "tenantSubID"
    }
    property {
      name  = "APIObjectId"
      value = "SPObject"
    }
    property {
      name  = "VaultName"
      value = "companykeyvault"
    }
    inventory_schedule {
      interval {
        minutes = 60
      }
    }
    agent_id = "keyfactorOrchestratorAgentID"
  }
}

output "store" {
  value = keyfactor_store.AKS1.store[0]
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
      store_ids      = [keyfactor_store.AKS1.store[0].keyfactor_id]
      store_type_ids = [keyfactor_store.AKS1.store[0].cert_store_type]
      alias          = ["terraform"]
    }
  }
}

output "pfxCertificate" {
  value = keyfactor_certificate.PFXCertificate.certificate[0]
}
