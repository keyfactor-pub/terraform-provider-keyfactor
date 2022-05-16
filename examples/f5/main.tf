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

resource "keyfactor_store" "f5_bigip" {
  provider        = keyfactor.command
  client_machine  = "f5_demo"
  store_path      = "https://companykeyvault.vault.azure.net/"
  agent_id        = "keyfactorOrchestratorAgentID"
  cert_store_type = 10
  property {
    PrimaryNode  = var.f5_primary_node
    PrimaryNodeCheckRetryWaitSecs = var.f5_primary_node_retry_wait_sec
    PrimaryNodeCheckRetryMax = var.f5_primary_node_retry_max
    F5Version = var.f5_version
  }
  inventory_schedule {
    interval {
      minutes = 60
    }
  }
}


resource "keyfactor_certificate" "PFXCertificate" {
  provider = keyfactor.command
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
}

resource "keyfactor_deploy_certificate" "test" {
  certificate_id = keyfactor_certificate.PFXCertificate.keyfactor_id
  password       = keyfactor_certificate.PFXCertificate.key_password
  store {
    certificate_store_id = keyfactor_store.f5_bigip.keyfactor_id
    alias                = "deploy1"
  }
}
