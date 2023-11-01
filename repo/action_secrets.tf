data "github_repository" "terraform_provider_keyfactor" {
  full_name = var.repo_path
}

#data "github_actions_public_key" "terraform_provider_keyfactor" {
#  repository = data.github_repository.terraform_provider_keyfactor.name
#}

# Actions Secrets
resource "github_actions_secret" "test_hostname" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "KEYFACTOR_HOSTNAME"
  plaintext_value = var.command_hostname
}

resource "github_actions_secret" "test_domain" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "KEYFACTOR_DOMAIN"
  plaintext_value = var.command_domain
}

resource "github_actions_secret" "test_username" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "KEYFACTOR_USERNAME"
  plaintext_value = var.test_username
}

resource "github_actions_secret" "test_user_password" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "KEYFACTOR_PASSWORD"
  plaintext_value = var.test_user_password
}

resource "github_actions_secret" "test_cert_password" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "TEST_CERTIFICATE_PASSWORD"
  plaintext_value = var.test_cert_password
}

resource "github_actions_secret" "test_store_password" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "TEST_CERTIFICATE_STORE_PASS"
  plaintext_value = var.test_store_password
}

resource "github_actions_secret" "test_certificate_id" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "TEST_CERTIFICATE_ID"
  plaintext_value = var.test_cert_id
}

resource "github_actions_secret" "test_certificate_cn" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "TEST_CERTIFICATE_CN"
  plaintext_value = var.test_cert_cn
}

resource "github_actions_secret" "test_certificate_thumbprint" {
  repository      = data.github_repository.terraform_provider_keyfactor.name
  secret_name     = "TEST_CERTIFICATE_THUMBPRINT"
  plaintext_value = var.test_cert_thumbprint
}