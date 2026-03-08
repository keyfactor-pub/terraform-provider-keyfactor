# keyfactor_certificate_template Data Source

Reads a Keyfactor Command Certificate Template by name or integer ID.

The `identifier` field accepts:
- An integer ID (e.g. `"5"`) — performs a direct lookup by ID
- A common name, display name, or template name (case-insensitive string match)

## Example Usage

### Look up by common name

```hcl
data "keyfactor_certificate_template" "webserver" {
  identifier = "WebServer"
}

# Reference the template ID in a certificate resource
resource "keyfactor_certificate" "example" {
  certificate_template      = data.keyfactor_certificate_template.webserver.common_name
  certificate_authority     = "MyDomain\\My-Issuing-CA"
  dns_sans                  = ["www.example.com"]
}
```

### Look up by integer ID

```hcl
data "keyfactor_certificate_template" "by_id" {
  identifier = "5"
}
```

## Argument Reference

### Required

* `identifier` - (String) Common name, display name, template name, or integer ID of the template to look up.

## Attributes Reference

* `id` - (Number) Integer ID of the certificate template.
* `common_name` - (String) Short name (common name) of the template.
* `template_name` - (String) Display name of the template.
* `display_name` - (String) Display name field from the server.
* `oid` - (String) Object ID of the template.
* `key_size` - (String) Minimum key size.
* `key_type` - (String) Key type (e.g. `RSA`, `ECC`).
* `key_types` - (String) Human-readable list of all supported key types.
* `forest_root` - (String) Forest root the template belongs to.
* `configuration_tenant` - (String) Configuration tenant.
* `key_archival` - (Boolean) Whether key archival is configured on the template.
* `friendly_name` - (String) Friendly name for the template.
* `key_retention` - (Number) Key retention policy value.
* `key_retention_days` - (Number) Days to retain private keys.
* `allowed_enrollment_types` - (Number) Bitmask: `0`=none, `1`=PFX, `2`=CSR, `3`=both.
* `use_allowed_requesters` - (Boolean) Whether enrollment is restricted to specific requesters.
* `allowed_requesters` - (List of String) Allowed requester security roles.
* `requires_approval` - (Boolean) Whether enrollments require approval.
* `allow_one_click_renewals` - (Boolean) Whether one-click renewals are allowed.
* `key_usage` - (Number) Key usage bitmask.
* `template_policy` - (Block) Enrollment policy settings. See the [resource documentation](../resources/certificate_template.md) for nested attribute details.
* `template_regexes` - (Block List) Subject field regex validation rules.
* `template_defaults` - (Block List) Default values for subject fields.
* `enrollment_fields` - (Block List) Custom enrollment fields.
* `metadata_fields` - (Block List) Metadata field associations.
* `extended_key_usages` - (Block List) Extended key usages.
* `key_algorithms` - (Block List) Supported key algorithms reported by the CA.
* `manageability` - (Number) Manageability level (v25+).
* `certificate_cleanup_enabled` - (Boolean) Whether certificate cleanup is enabled (v25+).
* `time_after_expiration` - (Number) Time after expiration value (v25+).
* `time_after_expiration_units` - (String) Units for time after expiration (v25+).
* `delete_with_archived_key` - (Boolean) Whether to delete certificates with archived key (v25+).
