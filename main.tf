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
    provider     = keyfactor.command
    account_name = "THEDEMODRIVE\\TestUser1"
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
    template_id_list = []
}



/*
resource "keyfactor_certificate" "pfx" {
    provider = keyfactor.command
    subject {
        subject_common_name         = "terraformtest21"
        subject_organization        = "Keyfactor"
        subject_locality            = "Prescott"
        subject_country             = "US"
        subject_organizational_unit = "SE"
        subject_state               = "AZ"
    }
    sans {
        san_ip4 = ["192.168.123.2", "172.51.2.4"]
        san_dns = []
        san_uri = []
    }
    metadata {
        name  = "Department"
        value = "Solutions Engineering"
    }
    metadata {
        name  = "Email-Contact"
        value = "hayden.roszell@keyfactor.com"
    }
    key_password          = "Ferrari10111"
    certificate_authority = "keyfactor.thedemodrive.com\\Keyfactor Demo Drive CA 1"
    cert_template         = "DDWebServer1yr"
}
*/

/*
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
*/