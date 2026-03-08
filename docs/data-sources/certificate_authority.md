# keyfactor_certificate_authority Data Source

Reads a Keyfactor Command Certificate Authority by name or integer ID.

## Example Usage

### By Name

```hcl
data "keyfactor_certificate_authority" "example" {
  identifier = "My-EJBCA-CA"
}
```

### By ID

```hcl
data "keyfactor_certificate_authority" "example" {
  identifier = "1"
}
```

## Argument Reference

* `identifier` - (Required, String) Name (logical name) or integer ID of the certificate authority to look up.

## Attributes Reference

All attributes from the `keyfactor_certificate_authority` resource are exported, except write-only secrets. See the [resource documentation](../resources/certificate_authority.md) for attribute descriptions.
