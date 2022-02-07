terraform {
  required_providers {
    keyfactor = {
      version = "~> 1.0.1"
      source  = "keyfactor.com/keyfactordev/keyfactor"
    }
  }
}

provider "keyfactor" {
  alias    = "command"
  hostname = "keyfactor.example.com"
}

resource "keyfactor_store" "IIS" {
  provider = keyfactor.command
  store {
    client_machine  = "keyfactor_demo1"
    store_path      = "IIS Personal"
    cert_store_type = 6
    agent_id        = "keyfactorOrchestratorAgentID"
    inventory_schedule {
      interval {
        minutes = 60
      }
    }
    password {
      value = "Ferrari10101"
    }
  }
}

output "store" {
  value = keyfactor_store.IIS.store[0]
}


resource "keyfactor_certificate" "PFXCertificate" {
  provider = keyfactor.command
  certificate {
    subject {
      subject_common_name         = "iis_terraform"
      subject_organization        = "example"
      subject_locality            = "Springfield"
      subject_country             = "US"
      subject_organizational_unit = "SE"
      subject_state               = "NA"
    }
    sans {
      san_uri = ["example.com"]
    }
    key_password          = "P@s5w0Rd2321!"
    certificate_authority = "keyfactor.example.com\\CA 1"
    cert_template         = "WebServer1yr"

    deployment {
      store_ids      = [keyfactor_store.IIS.store[0].keyfactor_id]
      store_type_ids = [keyfactor_store.IIS.store[0].cert_store_type]
      alias          = ["terraform"]
    }
  }
}

output "pfxCertificate" {
  value = keyfactor_certificate.PFXCertificate.certificate[0]
}