terraform {
  required_providers {
    keyfactor = {
      version = "~> 1.0.1"
      source  = "keyfactor.com/keyfactordev/keyfactor"
    }
  }
}

provider "keyfactor" {
  alias = "command"
  hostname = "keyfactor.example.com"
  kf_username = "username"
  kf_password = "password"
  dev_mode = false
}

resource "keyfactor_certificate" "PFXCertificate" {
  provider =                    keyfactor.command
  key_password =                ""
  subject_common_name =         ""
  subject_organization =        ""
  subject_locality =            ""
  subject_country =             ""
  subject_organizational_unit = ""
  subject_state =               ""
  certificate_authority =       ""
  cert_template =               ""
  certificate_format =          ""
  san_ip4 =                     ["", ""]
  san_dns =                     ["", ""]
}

output "certificate_sn" {
  value = keyfactor_certificate.PFXCertificate.serial_number
}