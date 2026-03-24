locals {
  # Use exactly one of certificate_template or certificate_enrollment_pattern.
  # Set the unused one to null so the provider's XOR validation is satisfied.
  tmpl    = var.certificate_template != "" ? var.certificate_template : null
  pattern = var.certificate_enrollment_pattern != "" ? var.certificate_enrollment_pattern : null
}

# -------------------------------------------------------------------------
# Example 1: Minimal PFX enrollment
#
# The simplest possible certificate — only the required fields.
# Keyfactor Command picks the key algorithm and size from the template
# defaults. The signed certificate and private key are returned in PEM
# format (provider default).
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "minimal_pfx" {
  common_name                    = "tf-demo-minimal-pfx${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password
}

# -------------------------------------------------------------------------
# Example 2: Full PFX enrollment
#
# Demonstrates every commonly used field:
#   - Explicit EC P-521 key algorithm
#   - DNS and IP SANs
#   - Custom metadata fields
#   - Automatic renewal when fewer than 30 days remain
#   - Explicit PEM output format
#
# Note: the template must allow EC keys and have KeyRetention enabled for
# the private key to be returned.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "full_pfx" {
  common_name                    = "tf-demo-full-pfx${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  # Explicit key algorithm — EC P-521
  key_type = "ECC"
  curve    = "P-521"

  # Subject alternative names
  dns_sans = [
    "tf-demo-full-pfx${var.suffix}.example.com",
    "alt.tf-demo-full-pfx${var.suffix}.example.com",
  ]
  ip_sans = ["10.0.0.1"]

  # Custom metadata tracked in Command
  metadata = {
    "Owner"         = "terraform-demo"
    "Email-Contact" = "infosec@example.com"
  }

  # Trigger automatic renewal when fewer than 30 days remain before expiry
  renewal_config = {
    renew_days = 30
  }

  certificate_format = "PFX"
}

# -------------------------------------------------------------------------
# Example 3: RSA 2048-bit key
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_2048" {
  common_name                    = "tf-demo-rsa2048${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "RSA"
  key_size = 2048
}

# -------------------------------------------------------------------------
# Example 4: RSA 3072-bit key
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_3072" {
  common_name                    = "tf-demo-rsa3072${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "RSA"
  key_size = 3072
}

# -------------------------------------------------------------------------
# Example 5: RSA 4096-bit key
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_4096" {
  common_name                    = "tf-demo-rsa4096${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "RSA"
  key_size = 4096
}

# -------------------------------------------------------------------------
# Example 6: RSA 8192-bit key
#
# Very large key — enrollment may take longer than other key sizes.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "rsa_8192" {
  common_name                    = "tf-demo-rsa8192${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "RSA"
  key_size = 8192
}

# -------------------------------------------------------------------------
# Example 7: ECC P-256 key
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ecc_p256" {
  common_name                    = "tf-demo-ecc256${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "ECC"
  curve    = "P-256"
}

# -------------------------------------------------------------------------
# Example 8: ECC P-384 key
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ecc_p384" {
  common_name                    = "tf-demo-ecc384${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "ECC"
  curve    = "P-384"
}

# -------------------------------------------------------------------------
# Example 9: ECC P-521 key
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ecc_p521" {
  common_name                    = "tf-demo-ecc521${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "ECC"
  curve    = "P-521"
}

# -------------------------------------------------------------------------
# Example 10: Ed25519 key
#
# Requires Command v11.7+ and a CA configured to issue Ed25519 certificates.
# Not all CAs or templates support this algorithm — the enrollment will fail
# with a CA error if it is not supported.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ed25519" {
  common_name                    = "tf-demo-ed25519${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "Ed25519"
}

# -------------------------------------------------------------------------
# Example 11: Ed448 key
#
# Requires Command v11.7+ and a CA explicitly configured for Ed448.
# Not widely supported — the enrollment will fail with a CA error if the
# CA or template does not support this algorithm.
# -------------------------------------------------------------------------
resource "keyfactor_certificate" "ed448" {
  common_name                    = "tf-demo-ed448${var.suffix}.example.com"
  certificate_authority          = var.certificate_authority
  certificate_template           = local.tmpl
  certificate_enrollment_pattern = local.pattern
  key_password                   = var.key_password

  key_type = "Ed448"
}
