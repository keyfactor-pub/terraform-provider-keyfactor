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


// Create a new identity in Keyfactor
resource "keyfactor_security_identity" "identity1" {
    provider = keyfactor.command
    account_name = "THEDEMODRIVE\\TestUser1"
}


// Create a new security role in Keyfactor and attach the identity represented by the resource identity1
resource "keyfactor_security_role" "kf_terraform_role1" {
    provider = keyfactor.command
    role_name = "Terraform1"
    description = "Role used to demonstrate Keyfactor's ability to integrate with Terraform."
    identities {
        account_name = keyfactor_security_identity.identity1.account_name
    }
    permissions = ["Monitoring:Read", "SecuritySettings:Modify"]
}

// Attach the role represented by the kf_terraform_role1 resource to template IDs 46 and 47
resource "keyfactor_attach_role" "role_attachment1" {
    provider = keyfactor.command
    role_name = keyfactor_security_role.kf_terraform_role1.role_name
    template_id_list = [46, 47]
}