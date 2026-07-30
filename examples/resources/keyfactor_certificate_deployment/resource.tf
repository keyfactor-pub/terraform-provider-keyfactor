# Lookup existing cert store using the client machine's name and the store path
data "keyfactor_certificate_store" "my_cert_store" {
  client_machine = "192.168.0.9"
  store_path     = "/home/azureuser/certs"
}

# Lookup existing certificate using the client machine's name and the certificate path
data "keyfactor_certificate" "ca_cert" {
  identifier   = "CommandCA1" #Certificate CN
  key_password = ""           # This is bad practice. Use TF_VAR_<variable_name> instead.
}

# Deploy the CA certificate to the certificate store
resource "keyfactor_certificate_deployment" "ca_cert_deployment" {
  certificate_id = data.keyfactor_certificate.ca_cert.certificate_id
  # The Keyfactor Command internal certificate ID
  certificate_store_id = data.keyfactor_certificate_store.my_cert_store.id # The Keyfactor Command certificate store ID
  certificate_alias    = data.keyfactor_certificate.ca_cert.thumbprint
  # Alias to use for the certificate in the store
  job_parameters = {
    #Optional entry parameters to provide to the deployment job. These will only be used if the orchestrator extension supports them.
    "Region"    = "us-east-1"
    "Account"   = "1234567890"
    "Arbitrary" = "Value"
  }
}

# Deploy without waiting for the store inventory to confirm the deployment.
# The apply completes as soon as Keyfactor Command accepts the management job,
# and fails early if the orchestrator reports that the job failed.
# fail_on_job_failure requires the Agent Management - Read permission
# (claim /agents/management/read/) in Keyfactor Command.
resource "keyfactor_certificate_deployment" "fast_deployment" {
  certificate_id       = data.keyfactor_certificate.ca_cert.certificate_id
  certificate_store_id = data.keyfactor_certificate_store.my_cert_store.id
  certificate_alias    = data.keyfactor_certificate.ca_cert.thumbprint

  # Do not poll the store inventory after submitting the deployment/removal job.
  skip_inventory_validation = true
  # Fail the run if the orchestrator job reports a final failure result.
  fail_on_job_failure = true
}

