---
page_title: "Resource keyfactor_certificate - terraform-provider-keyfactor"
subcategory: ""
description: |-
  Manages a certificate in Keyfactor Command using the /Enrollment and /Certificates APIs
---

# Resource keyfactor_certificate

Manages a certificate in Keyfactor Command using the `/Enrollment` and `/Certificates` APIs

## Example Usage

### Minimal PFX enrollment (certificate_template — pre-v25)

```terraform
# Minimal PFX enrollment — server generates the private key.
# For Command v25+, replace certificate_template with certificate_enrollment_pattern.
resource "keyfactor_certificate" "pfx" {
  common_name           = "my.example.com"
  certificate_authority = "MYCA\\My Issuing CA"
  certificate_template  = "2yrWebServer"
  key_password          = "MyStr0ngPassw0rd!"
}
```

### Minimal PFX enrollment (certificate_enrollment_pattern — v25+)

```terraform
# Minimal PFX enrollment using an enrollment pattern (Command v25+).
# certificate_authority is optional — Command automatically selects a CA
# associated with the pattern. Specify it only to pin to a particular CA.
resource "keyfactor_certificate" "pfx_pattern" {
  common_name                    = "my.example.com"
  certificate_enrollment_pattern = "2yrWebServer"
  key_password                   = "MyStr0ngPassw0rd!"
}
```

### Minimal CSR enrollment (certificate_template — pre-v25)

```terraform
# Minimal CSR enrollment — the private key never leaves the client.
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "example" {
  private_key_pem = tls_private_key.example.private_key_pem
  subject {
    common_name = "my.example.com"
  }
}

resource "keyfactor_certificate" "csr" {
  csr                   = tls_cert_request.example.cert_request_pem
  certificate_authority = "MYCA\\My Issuing CA"
  certificate_template  = "2yrWebServer"
}
```

### Minimal CSR enrollment (certificate_enrollment_pattern — v25+)

```terraform
# Minimal CSR enrollment using an enrollment pattern (Command v25+).
# certificate_authority is optional — Command automatically selects a CA
# associated with the pattern. Specify it only to pin to a particular CA.
resource "tls_private_key" "example_pattern" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "example_pattern" {
  private_key_pem = tls_private_key.example_pattern.private_key_pem
  subject {
    common_name = "my.example.com"
  }
}

resource "keyfactor_certificate" "csr_pattern" {
  csr                            = tls_cert_request.example_pattern.cert_request_pem
  certificate_enrollment_pattern = "2yrWebServer"
}
```

### Full PFX enrollment (certificate_template — pre-v25)

```terraform
# Full PFX enrollment with all optional fields — Command pre-v25 style.
resource "keyfactor_certificate" "pfx_full" {
  # Subject fields
  common_name         = "my.example.com"
  country             = "US"
  state               = "Ohio"
  locality            = "Cleveland"
  organization        = "Acme Corp"
  organizational_unit = "Engineering"

  # SANs
  dns_sans = ["my.example.com", "alt.example.com"]
  ip_sans  = ["192.168.1.10"]
  uri_sans = ["spiffe://cluster.local/ns/default/sa/my-service"]

  # Enrollment method
  certificate_authority = "MYCA\\My Issuing CA"
  certificate_template  = "2yrWebServer"

  # Key options (omit to accept CA defaults)
  key_type     = "RSA"
  key_size     = 4096
  key_password = "MyStr0ngPassw0rd!"

  # Display / organization
  friendly_name   = "my-cert"
  owner_role_name = "my-role"
  collection_id   = 6

  # Lifecycle
  expiry_warn_days = 90

  renewal_config = {
    renew_days      = 30
    revoke_on_renew = true
    force_renewal   = false
  }

  # Metadata keys must already exist in Keyfactor Command
  metadata = {
    "Email-Contact" = "admin@example.com"
    "Owner"         = "platform-team@example.com"
  }
}
```

### Full PFX enrollment (certificate_enrollment_pattern — v25+)

```terraform
# Command v25+ style — use certificate_enrollment_pattern instead of certificate_template.
resource "keyfactor_certificate" "pfx_full" {
  # Subject fields
  common_name         = "my.example.com"
  country             = "US"
  state               = "Ohio"
  locality            = "Cleveland"
  organization        = "Acme Corp"
  organizational_unit = "Engineering"

  # SANs
  dns_sans = ["my.example.com", "alt.example.com"]
  ip_sans  = ["192.168.1.10"]
  uri_sans = ["spiffe://cluster.local/ns/default/sa/my-service"]

  # Enrollment method
  # certificate_authority is optional when using an enrollment pattern —
  # Command automatically selects a CA associated with the pattern.
  # Specify it only if you need to pin to a particular CA.
  # certificate_authority          = "MYCA\\My Issuing CA"
  certificate_enrollment_pattern = "2yrWebServer"

  # Key options (omit to accept CA defaults)
  key_type     = "RSA"
  key_size     = 4096
  key_password = "MyStr0ngPassw0rd!"

  # Display / organization
  friendly_name   = "my-cert"
  owner_role_name = "my-role"
  collection_id   = 6

  # Lifecycle
  expiry_warn_days = 90

  renewal_config = {
    renew_days      = 30
    revoke_on_renew = true
    force_renewal   = false
  }

  # Metadata keys must already exist in Keyfactor Command
  metadata = {
    "Email-Contact" = "admin@example.com"
    "Owner"         = "platform-team@example.com"
  }
}
```

### Full CSR enrollment (certificate_template — pre-v25)

```terraform
# Full CSR enrollment with all subject fields and optional settings — Command pre-v25 style.
resource "tls_private_key" "csr_full" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "csr_full" {
  private_key_pem = tls_private_key.csr_full.private_key_pem

  subject {
    common_name         = "my.example.com"
    organization        = "Acme Corp"
    country             = "US"
    locality            = "Cleveland"
    organizational_unit = "Engineering"
    province            = "Ohio"
    street_address      = "123 Main St"
  }
}

resource "keyfactor_certificate" "csr_full" {
  csr = tls_cert_request.csr_full.cert_request_pem

  # Enrollment method
  certificate_authority = "MYCA\\My Issuing CA"
  certificate_template  = "2yrWebServer"

  # Display / organization
  owner_role_name = "my-role"
  collection_id   = 6

  # Lifecycle
  expiry_warn_days = 90

  renewal_config = {
    renew_days      = 30
    revoke_on_renew = true
    force_renewal   = false
  }

  # Metadata keys must already exist in Keyfactor Command
  metadata = {
    "Email-Contact" = "admin@example.com"
    "Owner"         = "platform-team@example.com"
  }
}
```

### Full CSR enrollment (certificate_enrollment_pattern — v25+)

```terraform
# Command v25+ style — use certificate_enrollment_pattern instead of certificate_template.
resource "tls_private_key" "csr_full" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "csr_full" {
  private_key_pem = tls_private_key.csr_full.private_key_pem

  subject {
    common_name         = "my.example.com"
    organization        = "Acme Corp"
    country             = "US"
    locality            = "Cleveland"
    organizational_unit = "Engineering"
    province            = "Ohio"
    street_address      = "123 Main St"
  }
}

resource "keyfactor_certificate" "csr_full" {
  csr = tls_cert_request.csr_full.cert_request_pem

  # Enrollment method
  # certificate_authority is optional when using an enrollment pattern —
  # Command automatically selects a CA associated with the pattern.
  # Specify it only if you need to pin to a particular CA.
  # certificate_authority          = "MYCA\\My Issuing CA"
  certificate_enrollment_pattern = "2yrWebServer"

  # Display / organization
  owner_role_name = "my-role"
  collection_id   = 6

  # Lifecycle
  expiry_warn_days = 90

  renewal_config = {
    renew_days      = 30
    revoke_on_renew = true
    force_renewal   = false
  }

  # Metadata keys must already exist in Keyfactor Command
  metadata = {
    "Email-Contact" = "admin@example.com"
    "Owner"         = "platform-team@example.com"
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `certificate_authority` (String) Name of the certificate authority to use for enrollment. Optional when using a certificate template or enrollment pattern — Command will automatically select a CA associated with the template or pattern. Required when enrolling against a standalone CA. Example: "MYCA\\My Issuing CA"
- `certificate_enrollment_pattern` (String) Either the `name` or internal `ID` (integer) indicating the enrollment pattern to use when requesting the certificate. If this value is not provided, the default enrollment pattern defined for the template provided in the request (see the Template parameter) will be used.

One of either the Template or the EnrollmentPatternId is required unless the enrollment is being done against a standalone CA. If both the Template and EnrollmentPatternId are provided, the settings from the enrollment pattern take precedence. If both are specified, the enrollment will fail if the Template does not match the one defined by the specified enrollment pattern. IMPORTANT: Requires Keyfactor Command v25.1.0+
- `certificate_format` (String) Optional: The output format to return the enrolled certificate in. Valid PFX enrollment options are: `PEM, PFX, JKS, Zip`. Valid CSR enrollment options are `PEM, DER`. Defaults to: `PEM`
- `certificate_template` (String) A string that sets the name of the certificate template that should be used to issue the certificate. The template short name should be used. See also EnrollmentPatternId.

One of either the Template or the EnrollmentPatternId is required unless the enrollment is being done against a standalone CA. If both the Template and EnrollmentPatternId are provided, the settings from the enrollment pattern take precedence. If both are specified, the enrollment will fail if the Template does not match the one defined by the specified enrollment pattern.

Important:  The template must be configured with at least one enrollment pattern in order to be used for enrollment (see POST Enrollment Patterns).
Note:  This parameter is considered deprecated as for Keyfactor Command v25.1.0 and may be removed in a future release.
- `collection_id` (Number) Optional certificate collection ID. This is required if enrollment permissions have been granted at the collection level. NOTE: This will *not* assign the cert to the specified collection ID; assignment is based the collection's associated query. For more information on collection permissions see the Keyfactor Command docs: https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/CertificatePermissions.htm?Highlight=collection%20permissions
- `common_name` (String) Subject common name (CN) of the certificate.
- `country` (String) Subject country of the certificate
- `csr` (String) Base-64 encoded certificate signing request (CSR)
- `curve` (String) ECC curve name for PFX enrollment (e.g. P-256, P-384, P-521). Only relevant when key_type=ECC. Populated from the issued certificate on read. Cannot be set when `csr` is also set.
- `dns_sans` (List of String) List of DNS names to use as subjects of the certificate. NOTE: This field **does not work with CSR enrollments**, all SANs should be included in the CSR. Additional SANs added by the CA during enrollment **will not** be reflected in this field
- `expiry_warn_days` (Number) Number of days before expiry to warn about the certificate. Defaults to 30 days.
- `friendly_name` (String) Only applicable for PFX enrollments. A friendly name for the certificate. If not provided, the common name will be used unless `use_cn_as_friendly_name` is set to `false`.
- `ip_sans` (List of String) List of DNS names to use as subjects of the certificate. NOTE: This field **does not work with CSR enrollments**, all SANs should be included in the CSR. Additional SANs added by the CA during enrollment **will not** be reflected in this field
- `key_password` (String, Sensitive) Password used to recover the private key from Keyfactor Command. NOTE: If no value is provided a random password will be generated for key recovery. This value is not stored and does not encrypt the private key in Terraform state. Also note that if a password is provided it must meet any password complexity requirements enforced by the CA template or creation will fail. Auto-generated passwords will be of length 32 and contain a minimum of 4 of the following: uppercase, lowercase, numeric, and special characters.
- `key_size` (Number) Key size in bits for PFX enrollment (e.g. 2048, 4096 for RSA; 256, 384, 521 for ECC). If omitted, the CA/template default is used. Populated from the issued certificate on read. Cannot be set when `csr` is also set.
- `key_type` (String) Key algorithm for PFX enrollment: RSA, ECC, Ed25519, Ed448. If omitted, the CA/template default is used. Populated from the issued certificate on read. Cannot be set when `csr` is also set.
- `locality` (String) Subject locality (L) of the certificate
- `metadata` (Map of String) Metadata key-value pairs to be attached to certificate. Set to null or an empty map to clear all metadata on the server. Changes are applied in-place (no certificate replacement).
- `organization` (String) Subject organization (O) of the certificate
- `organizational_unit` (String) Subject organizational unit (OU) of the certificate
- `owner_role_name` (String) A string containing the name of the security role assigned as the certificate owner. This name must match the existing name of the security role.

> [!NOTE]
> **Attribute contract**: omitting `owner_role_name` from config leaves ownership unmanaged -- Terraform never sends a clearing value, and drift from an out-of-band owner change is still surfaced on plan/refresh. Declaring an explicit empty string (`owner_role_name = ""`) is a declarative "clear the owner" sentinel: Terraform sends a PUT with no role identifier, which Keyfactor Command interprets as removing the certificate's owner.

Expanded Change Owner Permission: A user who holds the Certificates > Expanded Change Owner permission can set the certificate owner to any role within the permission sets they are a member of. This permission setting overrides the Certificates > Collections > Change Owner permission (both Global and Collection-level) if both are set.

Collections > Change Owner Permission:

Global or Collection Level—No Default Value: A user who holds only the Certificates > Collections > Change Owner permission at either the Global or Collection level can set the certificate owner to any role they belong to if there is not a default value populated from the enrollment pattern or existing certificate on a renewal.
Global or Collection Level—Default Value: A user who holds only the Certificates > Collections > Change Owner permission at either the Global or Collection level can change the default certificate owner to any role they belong to. If the default value populated from the enrollment pattern or existing certificate on a renewal is not a role held by the acting user, the this value will not be populated in the Certificate Owner Role field. The user will still be allowed to add a new owner value.
Note:  To assign a certificate owner, one of OwnerRoleId or OwnerRoleName is required, not both. A certificate owner is required if the enrollment pattern or system-wide settings Certificate Owner Role policy has been configured as Required.

> [!IMPORTANT]
> Only compatible with Keyfactor Command versions v12.3.0 and later.
- `renewal_config` (Attributes) Configuration for certificate renewal.
> [!IMPORTANT]
> This does not deploy the updated certificate to associated certificate store locations. To deploy the updated
> certificate you must define a "keyfactor_certificate_deployment" Terraform resource that references this
> certificate or deploy via the Command UI. (see [below for nested schema](#nestedatt--renewal_config))
- `revoke_on_destroy` (Boolean) Whether to revoke the certificate on resource `destroy`. IMPORTANT: If set to `false` the certificate will not be revoked on `destroy`ing operations. This means the certificate will need to be revoked outside of Terraform. Defaults to `true`.
- `state` (String) Subject state (ST) of the certificate
- `uri_sans` (List of String) List of URIs to use as subjects of the certificate. NOTE: This field **does not work with CSR enrollments**, all SANs should be included in the CSR. Additional SANs added by the CA during enrollment **will not** be reflected in this field
- `use_cn_as_friendly_name` (Boolean) Only applicable for PFX enrollments. Use the common name as the friendly name for the certificate. Defaults to `true`. NOTE: Keyfactor Command must be configured to `allow custom friendly name` for this to work under `Application Settings > Enrollment > PFX`.

### Read-Only

- `ca_certificate` (String) PEM formatted CA certificate
- `certificate_chain` (String) PEM formatted full certificate chain
- `certificate_id` (Number) Keyfactor Command certificate ID.
- `certificate_pem` (String) PEM formatted certificate
- `command_request_id` (Number) Keyfactor request ID.
- `enrollment_password` (String, Sensitive) The password used during certificate issuance. Also used to unlock PFX/PKCS12 and JKS keystores. Only returned if the certificate template has KeyRetention set to a value other than None. Will use `key_password` value if specified else will generate a random password of length12 with a minimum of 4 uppercase, 4 numeric, and 0 special characters. Review this provider's schema docs for more details: https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs#schema
- `id` (String) Read-only alias of `identifier` for Terraform framework compatibility.
- `identifier` (String) Keyfactor certificate identifier. This can be any of the following values: thumbprint, CN, or Keyfactor Command Certificate ID. If using CN to lookup the last issued certificate, the CN must be an exact match and if multiple certificates are returned the certificate that was most recently issued will be returned.
- `is_expired` (Boolean) Whether the certificate is expired. When true, Terraform will plan a certificate replacement on the next apply.
- `is_pending_revocation` (Boolean) Whether the certificate is pending revocation
- `is_revoked` (Boolean) Whether the certificate is revoked. When true, Terraform will plan a certificate replacement on the next apply.
- `issuer_dn` (String) Issuer distinguished name that signed the certificate
- `jks` (String, Sensitive) Base64 encoded JKS keystore containing the certificate, private key (if available), and certificate chain. Only returned if the certificate template has KeyRetention set to a value other than None, and the certificate was not enrolled using a CSR.
- `not_after` (String) Not After date of enrolled certificate
- `not_before` (String) Not Before date of enrolled certificate
- `pfx` (String, Sensitive) Base64 encoded PFX keystore containing the certificate, private key (if available), and certificate chain. Only returned if the certificate template has KeyRetention set to a value other than None.
- `private_key` (String, Sensitive) PEM formatted PKCS#1 private key imported if cert_template has KeyRetention set to a value other than None, and the certificate was not enrolled using a CSR.
- `revocation_effective_date` (String) The effective date of the certificate revocation
- `serial_number` (String) Serial number of newly enrolled certificate
- `thumbprint` (String) Thumbprint of newly enrolled certificate
- `zip` (String, Sensitive) Base64 encoded ZIP archive containing the certificate, private key (if available), and certificate chain in PEM and DER formats. Only returned if the certificate template has KeyRetention set to a value other than None.

<a id="nestedatt--renewal_config"></a>
### Nested Schema for `renewal_config`

Required:

- `renew_days` (Number) The number of days before the certificate expires to trigger renewal.

Optional:

- `force_renewal` (Boolean) Will force certificate to be renewed
- `revoke_on_renew` (Boolean) Whether the existing certificate should be revoked on renewal.

Read-Only:

- `renew_eligible` (Boolean) Calculated value indicating whether the certificate is eligible for renewal based on `renew_days`, current date, and certificate expiry date.

## Import

Import is supported using the following syntax:

```shell
terraform import keyfactor_certificate.mycert 65 # Where this is the ID of the certificate on Keyfactor
```
