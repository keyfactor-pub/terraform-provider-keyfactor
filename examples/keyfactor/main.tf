terraform {
  required_providers {
    keyfactor = {
      version = "~> 1.0.0"
      source  = "keyfactor.com/keyfactordev/keyfactor"
    }
  }
}

// It's recommended that credentials are exported as environment variables. See documentation.
provider "keyfactor" {
  alias       = "command"
  hostname    = "keyfactor.example.com"
  kf_username = "username"
  kf_password = "password"
}

// Create a new identity in Keyfactor
resource "keyfactor_security_identity" "identity1" {
  provider     = keyfactor.command
  account_name = "DOMAIN\\Test"
}

// Create a new security role in Keyfactor and attach the identity represented by the resource identity1
resource "keyfactor_security_role" "kf_terraform_role1" {
  provider    = keyfactor.command
  role_name   = "Terraform"
  description = "Role used to demonstrate Keyfactor's ability to integrate with Terraform."
  identities {
    account_name = keyfactor_security_identity.identity1.account_name
  }
  permissions = ["Monitoring:Read", "SecuritySettings:Modify"]
}

// Attach the role represented by the kf_terraform_role1 resource to template IDs 46 and 47
resource "keyfactor_attach_role" "role_attachment1" {
  provider         = keyfactor.command
  role_name        = keyfactor_security_role.kf_terraform_role1.role_name
  template_id_list = [46, 47]
}

resource "keyfactor_certificate" "DDWebServer1yr" {
  provider = keyfactor.command
  subject {
    subject_common_name = "terraformdeploytest1"
  }
  sans {
    san_dns = ["terraformdeploytest"]
  }
  key_password          = "P@s5w0Rd2321!"
  certificate_authority = "keyfactor.example.com\\CA 1"
  cert_template         = "WebServer1yr"
}

resource "keyfactor_deploy_certificate" "deploy" {
  provider       = keyfactor.command
  certificate_id = keyfactor_certificate.DDWebServer1yr.keyfactor_id
  password       = keyfactor_certificate.DDWebServer1yr.key_password

  store {
    certificate_store_id = "store_id1"
    alias                = "terraform_certificate1"
  }

  store {
    certificate_store_id = "store_id2"
    alias                = "terraform_certificate2"
  }

}
