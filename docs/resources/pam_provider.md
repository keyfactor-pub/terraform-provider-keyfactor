---
page_title: "keyfactor_pam_provider Resource - terraform-provider-keyfactor"
subcategory: ""
description: |-
  Manages a Keyfactor Command PAM Provider. Secret parameter values are write-only — the server stores them as GUID references and never returns the plaintext.
---

# keyfactor_pam_provider (Resource)

Manages a Keyfactor Command PAM Provider.

PAM providers are instances of a PAM provider type configured with connection parameters. Secret parameter values (`data_type = 2`) are stored by the server as opaque GUID references — the plaintext is never returned in API responses. This means:

- Terraform will not detect drift on secret param values modified outside Terraform.
- To rotate a secret, update the `value` in config and run `terraform apply`.

## Example Usage

```terraform
# Look up an existing PAM provider type to get its parameter IDs
data "keyfactor_pam_provider_type" "thycotic" {
  identifier = "Thycotic"
}

# PAM provider using a known provider type GUID and parameter IDs
resource "keyfactor_pam_provider" "example" {
  name             = "My Thycotic Provider"
  provider_type_id = data.keyfactor_pam_provider_type.thycotic.id

  param_values = [
    {
      param_id = data.keyfactor_pam_provider_type.thycotic.parameters[0].id
      name     = data.keyfactor_pam_provider_type.thycotic.parameters[0].name
      value    = "https://thycotic.example.com"
    },
    {
      param_id = data.keyfactor_pam_provider_type.thycotic.parameters[1].id
      name     = data.keyfactor_pam_provider_type.thycotic.parameters[1].name
      value    = var.thycotic_secret_key
    },
  ]
}

# PAM provider with no parameter values (all defaults)
resource "keyfactor_pam_provider" "minimal" {
  name             = "My Minimal Provider"
  provider_type_id = "c09bbfa5-a081-4194-9dd2-31f3cc3fabcc"
}
```

## Schema

### Required

- `name` (String) Name of the PAM provider.
- `provider_type_id` (String) GUID of the PAM provider type. Changing this value forces a new resource.

### Optional

- `area` (Number) Area (zone) integer identifier for this PAM provider.
- `param_values` (List of Object) Parameter values for this PAM provider. (see [below for nested schema](#nestedatt--param_values))
- `remote` (Boolean) Whether the PAM provider runs remotely.

### Read-Only

- `id` (String) Integer ID of the PAM provider in Keyfactor Command.

<a id="nestedatt--param_values"></a>
### Nested Schema for `param_values`

Required:

- `name` (String) Name of the PAM provider type parameter. Required by the Keyfactor API.
- `param_id` (Number) Integer ID of the PAM provider type parameter.
- `value` (String, Sensitive) Value for this parameter. For secret parameters (`data_type = 2`), this is write-only and will not drift even if modified outside Terraform.

## Import

PAM providers can be imported using their integer ID:

```shell
terraform import keyfactor_pam_provider.example 42
```

**Note:** `param_values` cannot be recovered on import and must be re-specified in configuration.
