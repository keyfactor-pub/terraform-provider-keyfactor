---
page_title: "keyfactor_pam_provider_type Resource - terraform-provider-keyfactor"
subcategory: ""
description: |-
  Manages a Keyfactor Command PAM Provider Type. PAM provider types define the parameter schema for PAM provider configurations. There is no update endpoint — any change to the type or its parameters forces a new resource (delete + recreate).
---

# keyfactor_pam_provider_type (Resource)

Manages a Keyfactor Command PAM Provider Type.

PAM provider types define the parameter schema (names, data types) used when configuring PAM providers. There is no server-side update endpoint for PAM provider types — all changes force a replace.

## Example Usage

```terraform
# PAM provider type with string and secret parameters
resource "keyfactor_pam_provider_type" "example" {
  name = "My Custom PAM Type"

  parameters = [
    {
      name           = "Hostname"
      display_name   = "PAM Server Hostname"
      data_type      = 1 # string
      instance_level = false
    },
    {
      name           = "Password"
      display_name   = "PAM Account Password"
      data_type      = 2 # secret
      instance_level = false
    },
  ]
}

# Minimal PAM provider type with no parameters
resource "keyfactor_pam_provider_type" "minimal" {
  name = "My Minimal PAM Type"
}
```

## Schema

### Required

- `name` (String) Name of the PAM provider type. Changing this value forces a new resource.

### Optional

- `parameters` (List of Object) Parameters defined for this PAM provider type. Any change to parameters forces a new resource. (see [below for nested schema](#nestedatt--parameters))

### Read-Only

- `id` (String) GUID identifier of the PAM provider type.

<a id="nestedatt--parameters"></a>
### Nested Schema for `parameters`

Required:

- `name` (String) Parameter name.

Optional:

- `display_name` (String) Human-readable display name for the parameter.
- `data_type` (Number) Data type: `1` = string, `2` = secret.
- `instance_level` (Boolean) Whether this parameter is configured at the instance level.

Read-Only:

- `id` (Number) Integer ID of the parameter.

## Import

PAM provider types can be imported using their GUID:

```shell
terraform import keyfactor_pam_provider_type.example c09bbfa5-a081-4194-9dd2-31f3cc3fabcc
```
