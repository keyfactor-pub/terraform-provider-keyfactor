locals {
  # Use exactly one of certificate_template or certificate_enrollment_pattern.
  # Set the unused one to null so the provider's XOR validation is satisfied.
  tmpl    = var.certificate_template != "" ? var.certificate_template : null
  pattern = var.certificate_enrollment_pattern != "" ? var.certificate_enrollment_pattern : null
}

# -------------------------------------------------------------------------
# Example 1: Minimal CSR enrollment
#
# The simplest possible CSR enrollment — only the required fields.
# The key type and size are determined by the CSR (RSA 2048 here).
# No private key is returned; it stays local in tls_private_key.minimal_csr.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "minimal_csr" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.minimal_csr.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 2: Full CSR enrollment
#
# Demonstrates every commonly used field for CSR enrollment:
#   - EC P-521 key (set in the CSR via keys.tf)
#   - DNS and IP SANs embedded in the CSR
#   - Custom metadata fields
#   - Automatic renewal when fewer than 30 days remain
#
# Note: no key_password — there is no server-side key to protect.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "full_csr" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.full_csr.cert_request_pem

  # Custom metadata tracked in Command
  metadata = {
    "Owner"         = "terraform-demo"
    "Email-Contact" = "infosec@example.com"
  }

  # Trigger automatic renewal when fewer than 30 days remain before expiry
  renewal_config = {
    renew_days = 30
  }
}

# -------------------------------------------------------------------------
# Example 3: RSA 2048-bit CSR
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_2048" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.rsa_2048.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 4: RSA 3072-bit CSR
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_3072" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.rsa_3072.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 5: RSA 4096-bit CSR
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_4096" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.rsa_4096.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 6: RSA 8192-bit CSR
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_8192" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.rsa_8192.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 7: ECC P-256 CSR
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ecc_p256" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.ecc_p256.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 8: ECC P-384 CSR
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ecc_p384" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.ecc_p384.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 9: ECC P-521 CSR
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ecc_p521" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.ecc_p521.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 10: Ed25519 CSR
#
# Requires the CA to support Ed25519 signatures.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ed25519" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = tls_cert_request.ed25519.cert_request_pem
}

# -------------------------------------------------------------------------
# Example 11: Ed448 CSR
#
# The CSR is generated by gen_ed448_csr.sh via the external data source
# (hashicorp/tls does not support Ed448). Requires openssl >= 1.1.1.
# Requires the CA to support Ed448 signatures.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ed448" {
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  csr                            = data.external.ed448_csr.result["csr"]
}
