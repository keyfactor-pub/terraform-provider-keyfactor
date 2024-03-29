---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "keyfactor_template_role_binding Resource - terraform-provider-keyfactor"
subcategory: ""
description: |-
  
---

# keyfactor_template_role_binding (Resource)



## Example Usage

```terraform
provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
  domain   = "mydomain.com"
}

resource "keyfactor_template_role_binding" "kf_terraform_role_attachment" {
  role_name            = "WebServerTerraformer" # The name of the role to grant template access to.
  template_short_names = ["2YearTestWebServer", "2yrWebServer"]
  # List of short names of templates the role will have access to.
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `role_name` (String) An string associated with a Keyfactor security role being attached. This is just the name field found on Keyfactor.

### Optional

- `template_short_names` (List of String) A list of certificate template short name in Keyfactor that the role will be attached to.

### Read-Only

- `id` (String) ID of template role binding.


