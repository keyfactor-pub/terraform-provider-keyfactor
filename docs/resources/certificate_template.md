# keyfactor_certificate_template Resource

Manages a Keyfactor Command Certificate Template.

Certificate templates are defined in the CA (Microsoft Active Directory or EJBCA) and synced into Keyfactor Command — they cannot be created or deleted through this provider. This resource manages template *settings* only (Update + Import). Use `terraform import` to bring an existing template under management.

Setting `allowed_enrollment_types = 0` effectively disables the template by preventing all enrollments.

## Example Usage

### Restrict enrollment to PFX only and require approval

```hcl
resource "keyfactor_certificate_template" "webserver" {
  # Import first: terraform import keyfactor_certificate_template.webserver 5

  allowed_enrollment_types = 1 # PFX only
  requires_approval        = true

  use_allowed_requesters = true
  allowed_requesters     = ["CertAdmins", "WebOps"]

  template_policy {
    allow_wildcards = false
    rfc_enforcement = true
  }
}
```

### Subject field validation with regexes

```hcl
resource "keyfactor_certificate_template" "restricted" {
  # Import first: terraform import keyfactor_certificate_template.restricted 12

  allowed_enrollment_types = 3 # PFX + CSR

  template_regexes {
    subject_part   = "CN"
    regex          = "^[a-z0-9-]+\\.example\\.com$"
    error          = "CN must be a subdomain of example.com"
    case_sensitive = false
  }

  template_defaults {
    subject_part = "O"
    value        = "Example Corp"
  }
}
```

## Lifecycle

Templates **cannot** be created or deleted through Terraform. Use `terraform import` to bring an existing template under management:

```shell
terraform import keyfactor_certificate_template.<name> <id>
```

Destroying a `keyfactor_certificate_template` resource only removes it from Terraform state — the template remains in Keyfactor Command.

## Argument Reference

### Optional

#### Enrollment Control

* `allowed_enrollment_types` - (Number) Bitmask of allowed enrollment types: `0`=none (disabled), `1`=PFX, `2`=CSR, `3`=both.
* `requires_approval` - (Boolean) Whether certificate enrollments require approval.
* `allow_one_click_renewals` - (Boolean) Whether one-click renewals are allowed.
* `key_usage` - (Number) Key usage bitmask.

#### Requesters

* `use_allowed_requesters` - (Boolean) Whether to restrict enrollment to specific security roles.
* `allowed_requesters` - (List of String) Security roles allowed to enroll with this template.

#### Key Retention

* `key_retention` - (Number) Key retention policy: `0`=None, `1`=SettingDriven, `2`=Always, `3`=Never.
* `key_retention_days` - (Number) Days to retain private keys.

#### Metadata

* `friendly_name` - (String) Friendly name for the template.

#### Policy Block

* `template_policy` - (Block, Optional) Enrollment policy settings. See [template_policy](#template_policy) below.

#### Subject Validation

* `template_regexes` - (Block List, Optional) Subject field regex validation rules. See [template_regexes](#template_regexes) below.
* `template_defaults` - (Block List, Optional) Default values for subject fields. See [template_defaults](#template_defaults) below.

#### Custom Fields

* `enrollment_fields` - (Block List, Optional) Custom enrollment fields for CSR/PFX enrollment. See [enrollment_fields](#enrollment_fields) below.
* `metadata_fields` - (Block List, Optional) Metadata field associations. See [metadata_fields](#metadata_fields) below.

### Read-Only

* `id` - (Number) Integer ID of the certificate template.
* `common_name` - (String) Short name (common name) of the template as defined in the CA.
* `template_name` - (String) Display name of the template as defined in the CA.
* `display_name` - (String) Display name field from the server.
* `oid` - (String) Object ID of the template.
* `key_size` - (String) Minimum key size from the CA.
* `key_type` - (String) Key type from the CA (e.g. `RSA`, `ECC`).
* `key_types` - (String) Human-readable list of all supported key types.
* `forest_root` - (String) Forest root the template belongs to.
* `configuration_tenant` - (String) Configuration tenant.
* `key_archival` - (Boolean) Whether key archival is configured on the template.
* `extended_key_usages` - (Block List) Extended key usages defined on the template. See [extended_key_usages](#extended_key_usages) below.
* `key_algorithms` - (Block List) Supported key algorithms reported by the CA. See [key_algorithms](#key_algorithms) below.
* `manageability` - (Number) Manageability level (v25+).
* `certificate_cleanup_enabled` - (Boolean) Whether certificate cleanup is enabled (v25+).
* `time_after_expiration` - (Number) Time after expiration value (v25+).
* `time_after_expiration_units` - (String) Units for time after expiration (v25+).
* `delete_with_archived_key` - (Boolean) Whether to delete certificates with archived key (v25+).

---

### template_policy

* `allow_key_reuse` - (Boolean) Whether certificate key reuse is allowed.
* `allow_wildcards` - (Boolean) Whether wildcard SANs are allowed.
* `rfc_enforcement` - (Boolean) Whether RFC enforcement (require DNS SAN) is enabled.
* `certificate_owner_role` - (Number) Certificate owner role: `0`=None, `1`=Requester, `2`=Specified.
* `default_certificate_owner_role_id` - (Number) ID of the default certificate owner role.
* `default_certificate_owner_role_name` - (String, Read-Only) Name of the default certificate owner role.
* `key_info` - (Block, Optional) Key algorithm constraints. See [key_info](#key_info) below.

### key_info

Each sub-block (`rsa`, `ecdsa`, `ed448`, `ed25519`) accepts:

* `bit_lengths` - (List of Number) Allowed bit lengths for the algorithm.
* `curves` - (List of String) Allowed curve OIDs (for ECDSA).

### template_regexes

* `subject_part` - (String, Required) Subject field name (e.g. `CN`, `O`, `OU`).
* `regex` - (String, Required) Regular expression to validate the field.
* `error` - (String, Optional) Error message shown when validation fails.
* `case_sensitive` - (Boolean, Optional) Whether the regex is case-sensitive.

### template_defaults

* `subject_part` - (String, Required) Subject field name.
* `value` - (String, Required) Default value for the field.

### enrollment_fields

* `id` - (Number, Read-Only) Server-assigned ID.
* `name` - (String, Required) Field name.
* `data_type` - (Number, Required) Data type: `1`=String, `2`=MultiValue.
* `options` - (List of String, Optional) Allowed values for multi-value fields.

### metadata_fields

* `id` - (Number, Read-Only) Server-assigned ID.
* `metadata_id` - (Number, Required) ID of the metadata field definition.
* `default_value` - (String, Optional) Default value.
* `validation` - (String, Optional) Validation regex.
* `enrollment` - (Number, Optional) Enrollment requirement: `0`=None, `1`=Optional, `2`=Required.
* `message` - (String, Optional) Help message shown during enrollment.
* `case_sensitive` - (Boolean, Optional) Whether validation is case-sensitive.

### extended_key_usages

* `id` - (Number) Server ID.
* `oid` - (String) OID string (e.g. `1.3.6.1.5.5.7.3.1` for Server Authentication).
* `display_name` - (String) Human-readable name.

### key_algorithms

* `algorithm` - (String) Algorithm name (e.g. `RSA`, `ECDSA`).
* `bit_lengths` - (List of Number) Supported bit lengths.
* `curves` - (List of String) Supported curve OIDs.

## Import

```shell
terraform import keyfactor_certificate_template.webserver 5
```

**Note:** All attribute values are populated from Keyfactor Command on import. No configuration values need to be known in advance.
