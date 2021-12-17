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
    kf_username = "HRoszell"
    kf_password = "Ferrari1!"
}

resource "keyfactor_store" "AKS1" {
    provider = keyfactor.command
    store {
        client_machine  = "hayden_aks_demo"
        store_path      = "https://hrkfdemovault.vault.azure.net/"
        cert_store_type = 106
        property {
            name  = "TenantID"
            value = "d5bc91c6-c809-49d4-b57f-7d4258d35ea4"
        }
        property {
            name  = "ResourceGroupName"
            value = "KF-Demos"
        }
        property {
            name  = "ApplicationId"
            value = "7523c1e7-c6c4-40fa-bbc9-a2f713c72c3a"
        }
        property {
            name  = "ClientSecret"
            value = "5kM7Q~WLMnRtKLjpgI7NowUT8d6ZWqNVttv52"
        }
        property {
            name  = "SubscriptionId"
            value = "b41bfe5f-2650-4574-9744-a2f5349ce861"
        }
        property {
            name  = "APIObjectId"
            value = "158a31ca-3793-483f-aeb9-3c9d52979c0d"
        }
        property {
            name  = "VaultName"
            value = "HRKFDemoVault"
        }
        inventory_schedule {
            interval {
                minutes = 60
            }
        }
        agent_id = "644aa071-c475-4b51-a7e6-b383040693b9"
        password {
            value = "Ferrari10101"
        }
    }
}

output "store" {
    value = keyfactor_store.AKS1.store[0]
}

resource "keyfactor_certificate" "PFXCertificate" {
    provider = keyfactor.command
    certificate {
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
        }
        metadata {
            name  = "Department"
            value = "Solutions Engineering"
        }
        metadata {
            name  = "Email-Contact"
            value = "hroszell@keyfactor.com"
        }
        key_password          = "Ferrari10111"
        certificate_authority = "keyfactor.thedemodrive.com\\Keyfactor Demo Drive CA 1"
        cert_template         = "DDWebServer1yr"
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