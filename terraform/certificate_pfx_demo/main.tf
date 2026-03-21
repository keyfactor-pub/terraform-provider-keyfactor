terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.0"
    }
  }
}

provider "keyfactor" {}

output "certificate_thumbprints" {
  description = "Thumbprints of all demo certificates."
  value = {
    minimal = keyfactor_certificate.minimal_pfx.thumbprint
    full    = keyfactor_certificate.full_pfx.thumbprint
    rsa2048 = keyfactor_certificate.rsa_2048.thumbprint
    rsa4096 = keyfactor_certificate.rsa_4096.thumbprint
    ecc256  = keyfactor_certificate.ecc_p256.thumbprint
    ecc384  = keyfactor_certificate.ecc_p384.thumbprint
    ecc521  = keyfactor_certificate.ecc_p521.thumbprint
    ed25519 = keyfactor_certificate.ed25519.thumbprint
  }
}

output "certificate_key_types" {
  description = "Key algorithms reported by the CA for each issued certificate."
  value = {
    minimal = keyfactor_certificate.minimal_pfx.key_type
    full    = keyfactor_certificate.full_pfx.key_type
    rsa2048 = keyfactor_certificate.rsa_2048.key_type
    rsa4096 = keyfactor_certificate.rsa_4096.key_type
    ecc256  = keyfactor_certificate.ecc_p256.key_type
    ecc384  = keyfactor_certificate.ecc_p384.key_type
    ecc521  = keyfactor_certificate.ecc_p521.key_type
    ed25519 = keyfactor_certificate.ed25519.key_type
  }
}

output "certificate_ids" {
  description = "Keyfactor Command integer IDs (used for import)."
  value = {
    minimal = keyfactor_certificate.minimal_pfx.certificate_id
    full    = keyfactor_certificate.full_pfx.certificate_id
    rsa2048 = keyfactor_certificate.rsa_2048.certificate_id
    rsa4096 = keyfactor_certificate.rsa_4096.certificate_id
    ecc256  = keyfactor_certificate.ecc_p256.certificate_id
    ecc384  = keyfactor_certificate.ecc_p384.certificate_id
    ecc521  = keyfactor_certificate.ecc_p521.certificate_id
    ed25519 = keyfactor_certificate.ed25519.certificate_id
  }
}

output "certificate_pems" {
  description = "Signed leaf certificate PEM for each demo certificate."
  value = {
    minimal = keyfactor_certificate.minimal_pfx.certificate_pem
    full    = keyfactor_certificate.full_pfx.certificate_pem
    rsa2048 = keyfactor_certificate.rsa_2048.certificate_pem
    rsa4096 = keyfactor_certificate.rsa_4096.certificate_pem
    ecc256  = keyfactor_certificate.ecc_p256.certificate_pem
    ecc384  = keyfactor_certificate.ecc_p384.certificate_pem
    ecc521  = keyfactor_certificate.ecc_p521.certificate_pem
    ed25519 = keyfactor_certificate.ed25519.certificate_pem
  }
}

output "private_keys" {
  description = "PEM private keys recovered from Keyfactor Command (requires KeyRetention on the template)."
  sensitive   = true
  value = {
    minimal = keyfactor_certificate.minimal_pfx.private_key
    full    = keyfactor_certificate.full_pfx.private_key
    rsa2048 = keyfactor_certificate.rsa_2048.private_key
    rsa4096 = keyfactor_certificate.rsa_4096.private_key
    ecc256  = keyfactor_certificate.ecc_p256.private_key
    ecc384  = keyfactor_certificate.ecc_p384.private_key
    ecc521  = keyfactor_certificate.ecc_p521.private_key
    ed25519 = keyfactor_certificate.ed25519.private_key
  }
}
