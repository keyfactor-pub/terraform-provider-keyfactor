output "certificate_thumbprints" {
  description = "Thumbprints of all demo CSR-enrolled certificates."
  value = {
    minimal = keyfactor_certificate.minimal_csr.thumbprint
    full    = keyfactor_certificate.full_csr.thumbprint
    rsa2048 = keyfactor_certificate.rsa_2048.thumbprint
    rsa3072 = keyfactor_certificate.rsa_3072.thumbprint
    rsa4096 = keyfactor_certificate.rsa_4096.thumbprint
    rsa8192 = keyfactor_certificate.rsa_8192.thumbprint
    ecc256  = keyfactor_certificate.ecc_p256.thumbprint
    ecc384  = keyfactor_certificate.ecc_p384.thumbprint
    ecc521  = keyfactor_certificate.ecc_p521.thumbprint
    ed25519 = keyfactor_certificate.ed25519.thumbprint
    ed448   = keyfactor_certificate.ed448.thumbprint
  }
}

output "certificate_key_types" {
  description = "Key algorithms reported by the CA for each issued certificate."
  value = {
    minimal = keyfactor_certificate.minimal_csr.key_type
    full    = keyfactor_certificate.full_csr.key_type
    rsa2048 = keyfactor_certificate.rsa_2048.key_type
    rsa3072 = keyfactor_certificate.rsa_3072.key_type
    rsa4096 = keyfactor_certificate.rsa_4096.key_type
    rsa8192 = keyfactor_certificate.rsa_8192.key_type
    ecc256  = keyfactor_certificate.ecc_p256.key_type
    ecc384  = keyfactor_certificate.ecc_p384.key_type
    ecc521  = keyfactor_certificate.ecc_p521.key_type
    ed25519 = keyfactor_certificate.ed25519.key_type
    ed448   = keyfactor_certificate.ed448.key_type
  }
}

output "certificate_ids" {
  description = "Keyfactor Command integer IDs (used for import)."
  value = {
    minimal = keyfactor_certificate.minimal_csr.certificate_id
    full    = keyfactor_certificate.full_csr.certificate_id
    rsa2048 = keyfactor_certificate.rsa_2048.certificate_id
    rsa3072 = keyfactor_certificate.rsa_3072.certificate_id
    rsa4096 = keyfactor_certificate.rsa_4096.certificate_id
    rsa8192 = keyfactor_certificate.rsa_8192.certificate_id
    ecc256  = keyfactor_certificate.ecc_p256.certificate_id
    ecc384  = keyfactor_certificate.ecc_p384.certificate_id
    ecc521  = keyfactor_certificate.ecc_p521.certificate_id
    ed25519 = keyfactor_certificate.ed25519.certificate_id
    ed448   = keyfactor_certificate.ed448.certificate_id
  }
}

output "certificate_pems" {
  description = "Signed leaf certificate PEM for each demo certificate."
  value = {
    minimal = keyfactor_certificate.minimal_csr.certificate_pem
    full    = keyfactor_certificate.full_csr.certificate_pem
    rsa2048 = keyfactor_certificate.rsa_2048.certificate_pem
    rsa3072 = keyfactor_certificate.rsa_3072.certificate_pem
    rsa4096 = keyfactor_certificate.rsa_4096.certificate_pem
    rsa8192 = keyfactor_certificate.rsa_8192.certificate_pem
    ecc256  = keyfactor_certificate.ecc_p256.certificate_pem
    ecc384  = keyfactor_certificate.ecc_p384.certificate_pem
    ecc521  = keyfactor_certificate.ecc_p521.certificate_pem
    ed25519 = keyfactor_certificate.ed25519.certificate_pem
    ed448   = keyfactor_certificate.ed448.certificate_pem
  }
}

output "private_keys" {
  description = "PEM private keys generated locally by the TLS provider. Store these securely : they live in Terraform state."
  sensitive   = true
  value = {
    minimal = tls_private_key.minimal_csr.private_key_pem
    full    = tls_private_key.full_csr.private_key_pem
    rsa2048 = tls_private_key.rsa_2048.private_key_pem
    rsa3072 = tls_private_key.rsa_3072.private_key_pem
    rsa4096 = tls_private_key.rsa_4096.private_key_pem
    rsa8192 = tls_private_key.rsa_8192.private_key_pem
    ecc256  = tls_private_key.ecc_p256.private_key_pem
    ecc384  = tls_private_key.ecc_p384.private_key_pem
    ecc521  = tls_private_key.ecc_p521.private_key_pem
    ed25519 = tls_private_key.ed25519.private_key_pem
    # ed448 private key is stored in .ed448_key.pem (not in Terraform state)
  }
}
