locals {
  # Use exactly one of certificate_template or certificate_enrollment_pattern.
  # Set the unused one to null so the provider's XOR validation is satisfied.
  tmpl    = var.certificate_template != "" ? var.certificate_template : null
  pattern = var.certificate_enrollment_pattern != "" ? var.certificate_enrollment_pattern : null

  # var.suffix defaults to "_TF" for non-DNS resource naming, but an
  # underscore embedded in a certificate common name / SAN makes this lab's
  # EJBCA/OpenBao backend reject the enrollment outright with a generic
  # "invalid custom extension or certificate policy OIDs" error (confirmed
  # 2026-08-08: identical CSR requests succeed with a hyphen in the hostname
  # and fail only with an underscore -- this is CA-side hostname/RFC policy
  # enforcement, not a provider bug). dns_suffix swaps underscores for
  # hyphens so hostnames (used in keys.tf) stay DNS-valid regardless of what
  # var.suffix is set to.
  dns_suffix = replace(var.suffix, "_", "-")
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

  # Custom metadata tracked in Command (in-place updatable; cleared on server when omitted).
  # Only "Email-Contact" is set -- kfclab defines no "Owner" metadata field, and Command
  # rejects unknown metadata field names with "Invalid Metadata Name: 'Owner'" (confirmed
  # 2026-08-07). Setting metadata_email="" omits this block entirely, same as removing it
  # from config.
  metadata = var.metadata_email != "" ? {
    "Email-Contact" = var.metadata_email
  } : null

  # Trigger automatic renewal when fewer than renew_days remain (in-place updatable; disabled when omitted)
  # Setting renew_days=0 omits this block — same as removing it from config.
  renewal_config = var.renew_days > 0 ? {
    renew_days = var.renew_days
  } : null
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
