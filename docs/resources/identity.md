---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "keyfactor_identity Resource - terraform-provider-keyfactor"
subcategory: ""
description: |-
  
---

# keyfactor_identity (Resource)



## Example Usage

```terraform
provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

resource "keyfactor_identity" "identity" {
  account_name = "COMMAND\\your_username"                # your_domain\\your_username
  roles        = ["EnrollPFX", "Administrator", "Nginx"] # List of existing role names to assign to the identity
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_name` (String) A string containing the account name for the security identity. For Active Directory user and groups, this will be in the form DOMAIN\\user or group name

### Optional

- `roles` (List of String) An array containing the role IDs that the identity is attached to.

### Read-Only

- `id` (Number) An integer containing the Keyfactor Command identifier for the security identity.
- `identity_type` (String) A string indicating the type of identity—User or Group.
- `valid` (Boolean) A Boolean that indicates whether the security identity's audit XML is valid (true) or not (false). A security identity may become invalid if Keyfactor Command determines that it appears to have been tampered with.

## Import

Import is supported using the following syntax:

```shell
terraform import keyfactor_security_identity.identity 'mykfdomain\\myusername'  # The user/group name to import
```
