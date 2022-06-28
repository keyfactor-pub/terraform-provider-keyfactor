terraform {
    required_providers {
        keyfactor = {
            version = "~> 1.0.0"
            source  = "keyfactor.com/keyfactordev/keyfactor"
        }
    }
}

provider "keyfactor" {
    alias       = "command"
    hostname    = "sedemo.thedemodrive.com"
}

resource "keyfactor_certificate" "DDWebServer1yr" {
    provider = keyfactor.command
    subject {
        subject_common_name         = "terraformdeploytest1"
    }
    sans {
        san_dns = ["terraformdeploytest"]
    }
    key_password          = "Ferrari10111"
    certificate_authority = "keyfactor.thedemodrive.com\\Keyfactor Demo Drive CA 1"
    cert_template         = "DDWebServer1yr"

    metadata = {
        Department  = "Engineering"
        Email-Contact = "admin@example.com"
    }
}

output "privatekey" {
    value = keyfactor_certificate.DDWebServer1yr.private_key
    sensitive = true
}
