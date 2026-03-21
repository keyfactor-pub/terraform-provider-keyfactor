# -------------------------------------------------------------------------
# Private keys and CSRs — generated locally by the hashicorp/tls provider.
#
# WARNING: Private keys are stored in Terraform state. Use a remote backend
# with encryption at rest (e.g. S3 + KMS) for production workloads.
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Minimal — RSA 2048 (CSR with CN only)
# -------------------------------------------------------------------------
resource "tls_private_key" "minimal_csr" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "minimal_csr" {
  private_key_pem = tls_private_key.minimal_csr.private_key_pem
  subject {
    common_name = "tf-demo-minimal-csr${var.suffix}.example.com"
  }
}

# -------------------------------------------------------------------------
# Full — EC P-521 with SANs
# -------------------------------------------------------------------------
resource "tls_private_key" "full_csr" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P521"
}

resource "tls_cert_request" "full_csr" {
  private_key_pem = tls_private_key.full_csr.private_key_pem
  subject {
    common_name = "tf-demo-full-csr${var.suffix}.example.com"
  }
  dns_names    = ["tf-demo-full-csr${var.suffix}.example.com", "alt.tf-demo-full-csr${var.suffix}.example.com"]
  ip_addresses = ["10.0.0.1"]
}

# -------------------------------------------------------------------------
# RSA 2048-bit key
# -------------------------------------------------------------------------
resource "tls_private_key" "rsa_2048" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "rsa_2048" {
  private_key_pem = tls_private_key.rsa_2048.private_key_pem
  subject {
    common_name = "tf-demo-csr-rsa2048${var.suffix}.example.com"
  }
}

# -------------------------------------------------------------------------
# RSA 4096-bit key
# -------------------------------------------------------------------------
resource "tls_private_key" "rsa_4096" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "rsa_4096" {
  private_key_pem = tls_private_key.rsa_4096.private_key_pem
  subject {
    common_name = "tf-demo-csr-rsa4096${var.suffix}.example.com"
  }
}

# -------------------------------------------------------------------------
# ECC P-256 key
# -------------------------------------------------------------------------
resource "tls_private_key" "ecc_p256" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "ecc_p256" {
  private_key_pem = tls_private_key.ecc_p256.private_key_pem
  subject {
    common_name = "tf-demo-csr-ecc256${var.suffix}.example.com"
  }
}

# -------------------------------------------------------------------------
# ECC P-384 key
# -------------------------------------------------------------------------
resource "tls_private_key" "ecc_p384" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "tls_cert_request" "ecc_p384" {
  private_key_pem = tls_private_key.ecc_p384.private_key_pem
  subject {
    common_name = "tf-demo-csr-ecc384${var.suffix}.example.com"
  }
}

# -------------------------------------------------------------------------
# ECC P-521 key
# -------------------------------------------------------------------------
resource "tls_private_key" "ecc_p521" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P521"
}

resource "tls_cert_request" "ecc_p521" {
  private_key_pem = tls_private_key.ecc_p521.private_key_pem
  subject {
    common_name = "tf-demo-csr-ecc521${var.suffix}.example.com"
  }
}

# -------------------------------------------------------------------------
# Ed25519 key
#
# Requires the CA to support Ed25519 signatures.
# -------------------------------------------------------------------------
resource "tls_private_key" "ed25519" {
  algorithm = "ED25519"
}

resource "tls_cert_request" "ed25519" {
  private_key_pem = tls_private_key.ed25519.private_key_pem
  subject {
    common_name = "tf-demo-csr-ed25519${var.suffix}.example.com"
  }
}
