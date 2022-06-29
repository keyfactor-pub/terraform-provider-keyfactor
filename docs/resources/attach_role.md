---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "keyfactor_attach_role Resource - terraform-provider-keyfactor"
subcategory: "Security & Authentication"
description: |-
Terraform resource used to attach Keyfactor security roles for purposes of permission management
---

# keyfactor_attach_role (Resource)

# keyfactor_attach_role (Resource)
The ```keyfactor_attach_role``` resource is used to attach Keyfactor security roles to various Keyfactor elements. As of
now, this resource can be used to attach the role represented by the resource as an allowed requestor on Keyfactor
certificate templates. Templates and associated roles must already exist in Keyfactor, but it is recommended that the role
be created speficially for use by this resource. This is because Terraform will attempt to attach the templates exactly as
configured. Said differently, if a role is configured in Keyfactor and an administrator sets the role as an allowed requestor
on a template, and subsequently uses this resource to attach the role to another template, the configuration set in the
Command portal will not persist. For this reason, it's recommended that Terraform be used to create the Keyfactor security
role.

## Example Usage
The following configuration attaches the role as configured by the ```role_name``` as an allowed requester to Keyfactor
certificate templates with IDs 46 and 47. Template IDs can be found by accessing the Keyfactor Command API.
```terraform
// Attach the role represented by the kf_terraform_role1 resource to template IDs 46 and 47
resource "keyfactor_attach_role" "role_attachment1" {
    role_name = keyfactor_security_role.kf_terraform_role1.role_name
    template_id_list = [46, 47]
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **role_name** (String) An string associated with a Keyfactor security role being attached. This is just the name field found on Keyfactor.

### Optional

- **id** (String) The ID of this resource.
- **template_id_list** (Set of Number) A list of integers associaed with certificate templates in Keyfactor that the role will be attached to.

