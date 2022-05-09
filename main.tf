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

resource "keyfactor_security_role" "import_test" {
    description = "Role generated to perform Terraform acceptance test. If this role exists, it can be deleted."
    permissions = [
        "CertificateEnrollment:CsrGeneration",
        "CertificateEnrollment:EnrollCSR",
        "CertificateEnrollment:EnrollPFX",
        "API:Read",
        "CertificateCollections:Modify"
    ]
    role_name   = "terraform_acctest-c2plk6vbeh"
}

/*
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
}
*/

// AKV: 6175d9f2-b7e4-40a2-a3c3-9acb91cdeae5
// EJBCA JKS: e9f9d8ef-1204-4ae3-a41f-aa761275aa85
/*
resource "keyfactor_deploy_certificate" "test" {
    provider = keyfactor.command
    certificate_id = keyfactor_certificate.DDWebServer1yr.keyfactor_id
    password       = keyfactor_certificate.DDWebServer1yr.key_password

    store {
        certificate_store_id = "6175d9f2-b7e4-40a2-a3c3-9acb91cdeae5"
        alias                = "cooltest1"
    }

    store {
        certificate_store_id = "e9f9d8ef-1204-4ae3-a41f-aa761275aa85"
        alias                = "cooltest2"
    }

}
*/



/*
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