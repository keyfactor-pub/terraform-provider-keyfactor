output "certificate_thumbprints" {
  description = "Thumbprints of all demo certificates."
  value = {
    minimal = keyfactor_certificate.minimal_pfx.thumbprint
    full    = keyfactor_certificate.full_pfx.thumbprint
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
    minimal = keyfactor_certificate.minimal_pfx.key_type
    full    = keyfactor_certificate.full_pfx.key_type
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
    minimal = keyfactor_certificate.minimal_pfx.certificate_id
    full    = keyfactor_certificate.full_pfx.certificate_id
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
    minimal = keyfactor_certificate.minimal_pfx.certificate_pem
    full    = keyfactor_certificate.full_pfx.certificate_pem
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
  description = "PEM private keys recovered from Keyfactor Command (requires KeyRetention on the template)."
  sensitive   = true
  value = {
    minimal = keyfactor_certificate.minimal_pfx.private_key
    full    = keyfactor_certificate.full_pfx.private_key
    rsa2048 = keyfactor_certificate.rsa_2048.private_key
    rsa3072 = keyfactor_certificate.rsa_3072.private_key
    rsa4096 = keyfactor_certificate.rsa_4096.private_key
    rsa8192 = keyfactor_certificate.rsa_8192.private_key
    ecc256  = keyfactor_certificate.ecc_p256.private_key
    ecc384  = keyfactor_certificate.ecc_p384.private_key
    ecc521  = keyfactor_certificate.ecc_p521.private_key
    ed25519 = keyfactor_certificate.ed25519.private_key
    ed448   = keyfactor_certificate.ed448.private_key
  }
}

# ---------------------------------------------------------------------------
# Data source gap fill: look up the minimal_pfx certificate by thumbprint and
# the configured enrollment pattern by name, and assert they agree with the
# resources/variables that produced them.
# ---------------------------------------------------------------------------
data "keyfactor_certificate" "minimal_pfx" {
  identifier = keyfactor_certificate.minimal_pfx.thumbprint

  depends_on = [keyfactor_certificate.minimal_pfx]
}

data "keyfactor_enrollment_pattern" "demo" {
  count      = local.pattern != null ? 1 : 0
  identifier = local.pattern
}

output "certificate_datasource_readback_matches" {
  description = "True if data.keyfactor_certificate's view of minimal_pfx agrees with the resource's own state."
  value       = data.keyfactor_certificate.minimal_pfx.identifier == keyfactor_certificate.minimal_pfx.thumbprint
}

output "enrollment_pattern_id" {
  description = "ID of the configured enrollment pattern, read via data.keyfactor_enrollment_pattern (null when certificate_template is used instead)."
  value       = local.pattern != null ? data.keyfactor_enrollment_pattern.demo[0].id : null
}
