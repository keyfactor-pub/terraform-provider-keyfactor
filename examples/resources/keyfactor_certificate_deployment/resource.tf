provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

## PFX Enrollment
resource "keyfactor_certificate" "PFXCertificate" {
  subject = {
    # Certificate subject metadata
    subject_common_name         = "mypfx.kfdelivery.com"
    subject_organization        = "Keyfactor"
    subject_locality            = "Cleveland"
    subject_country             = "US"
    subject_organizational_unit = "Software Development"
    subject_state               = "OH"
  }

  # Optional SANs
  ip_sans      = ["192.168.123.2", "172.51.2.4"] # Optional IP SANs
  dns_sans     = ["meow.example.com", "meow2"]   # Optional DNS SANs
  key_password = "my certificate password!"
  # The password for the certificate. Note: This is bad practice, use TF_VAR_<variable_name> instead.
  certificate_authority = "COMMAND\\MY_CA_01" # Keyfactor CA to use to handle the certificate request.
  certificate_template  = "2yrWebServer"      # The template shortname to use for the certificate.
}

resource "keyfactor_certificate_store" "iis_trusted_roots" {
  client_machine = "myorchestrator01"                     # Orchestrator client name
  store_path     = "IIS Trusted Roots"                    # Varies based on store type
  agent_id       = "c2b2084f-3d89-4ded-bb8b-b4e0e74d2b59" # Orchestrator GUID
  store_type     = "IIS"                                  # Must exist in KeyFactor
  properties = {
    # Optional properties based on the store type
    UseSSL = true
  }
  inventory_schedule = "60m" # How often to update the inventory
  container_id       = 2     # ID of the KeyFactor container
  password           = "my store password!"
  # The password for the certificate store. Note: This is bad practice, use TF_VAR_<variable_name> instead.
}

resource "keyfactor_certificate_deployment" "PFXCertificateDeployment" {
  certificate_id       = keyfactor_certificate.PFXCertificate.id                          # ID of the certificate to deploy
  certificate_store_id = keyfactor_certificate_store.iis_trusted_roots.id                 # UUID of the certificate store to deploy to
  certificate_alias    = keyfactor_certificate.PFXCertificate.subject.subject_common_name # Alias to use for the certificate in the store
}