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

resource "keyfactor_store" "f5_bigip" {
  provider = keyfactor.command
  store {
    client_machine  = "f5_demo"
    store_path      = "https://companykeyvault.vault.azure.net/"
    agent_id        = "keyfactorOrchestratorAgentID"
    cert_store_type = 10
    property {
      name  = "PrimaryNode"
      value = var.f5_primary_node
    }
    property {
      name  = "PrimaryNodeCheckRetryWaitSecs"
      value = var.f5_primary_node_retry_wait_sec
    }
    property {
      name  = "PrimaryNodeCheckRetryMax"
      value = var.f5_primary_node_retry_max
    }
    property {
      name  = "F5Version"
      value = var.f5_version
    }
    inventory_schedule {
      interval {
        minutes = 60
      }
    }
  }
}

output "store" {
  value = keyfactor_store.f5_bigip.store[0]
}


resource "keyfactor_certificate" "PFXCertificate" {
  provider = keyfactor.command
  certificate {
    subject {
      subject_common_name         = "f5_terraform"
      subject_organization        = "example"
      subject_locality            = "Springfield"
      subject_country             = "US"
      subject_organizational_unit = "SE"
      subject_state               = "NA"
    }
    sans {
      san_uri = [var.f5_primary_node]
    }
    key_password          = "P@s5w0Rd2321!"
    certificate_authority = "keyfactor.example.com\\CA 1"
    cert_template         = "WebServer1yr"

    deployment {
      store_ids      = [keyfactor_store.f5_bigip.store[0].keyfactor_id]
      store_type_ids = [keyfactor_store.f5_bigip.store[0].cert_store_type]
      alias          = ["terraform"]
    }
  }
}

output "pfxCertificate" {
  value = keyfactor_certificate.PFXCertificate.certificate[0]
}
