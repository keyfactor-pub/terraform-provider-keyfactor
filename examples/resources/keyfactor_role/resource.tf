provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

resource "keyfactor_role" "kf_terraform_role" {
  name        = "Terraform" # Name of the role to create
  description = "Role used to demonstrate Keyfactor's ability to integrate with Terraform."
  # Description of the role to create
  permissions = distinct([
    # List of valid permissions to assign to the role
    "AdminPortal:Read",
    "AdminPortal:Read", #Note the duplicate entry here
    "Certificates:Read",
    "Certificates:EditMetadata",
    "Certificates:Import",
    "Certificates:Recover",
    "Certificates:Revoke",
    "CertificateCollections:Modify",
    "PkiManagement:Read",
    "PkiManagement:Modify",
    "CertificateStoreManagement:Read",
    "CertificateStoreManagement:Modify",
    "API:Read",
    "CertificateStoreManagement:Schedule",
    "CertificateEnrollment:EnrollPFX",
    "CertificateEnrollment:EnrollCSR",
    "Certificates:Delete",
    "Certificates:ImportPrivateKey",
    "CertificateEnrollment:CsrGeneration",
    "CertificateEnrollment:PendingCsr"
  ])
}