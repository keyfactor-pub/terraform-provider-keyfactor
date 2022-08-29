---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "keyfactor_certificate_store Data Source - terraform-provider-keyfactor"
subcategory: ""
description: |-
  
---

# keyfactor_certificate_store (Data Source)



## Example Usage

```terraform
provider "keyfactor" {
  username = "COMMAND\\your_username"
  password = "your_api_password"
  hostname = "mykfinstance.kfdelivery.com"
}

data "keyfactor_certificate_store" "iis_personal" {
  keyfactor_id = "9f8855f1-80ff-4475-89ec-d82accb32cea" #The Keyfactor GUID of an existing certificate store.
  password     = "my store password!"                   #The password for the certificate store. Note: This is bad practice, use TF_VAR_<variable_name> instead.
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `id` (String) Keyfactor certificate store GUID.

### Optional

- `agent_assigned` (Boolean) Bool indicating if there is an orchestrator assigned to the new certificate store.
- `approved` (Boolean) Bool that indicates the approval status of store created. Default is true, omit if unsure.
- `container_name` (String) Name of certificate store's associated container, if applicable.
- `create_if_missing` (Boolean) Bool that indicates if the store should be created with information provided. Valid only for JKS type, omit if unsure.
- `inventory_schedule` (String) Inventory schedule for new certificate store.
- `password` (String, Sensitive) Sets password for certificate store.
- `properties` (Map of String) Certificate properties specific to certificate store type configured as key-value pairs.
- `set_new_password_allowed` (Boolean) Indicates whether the store password can be changed.

### Read-Only

- `agent_id` (String) String indicating the Keyfactor Command GUID of the orchestrator for the created store.
- `certificates` (List of Number) A list of certificate IDs associated with the certificate store.
- `client_machine` (String) Client machine name; value depends on certificate store type. See API reference guide
- `container_id` (Number) Container identifier of the store's associated certificate store container.
- `store_path` (String) Path to the new certificate store on a target. Format varies depending on type.
- `store_type` (String) Short name of certificate store type. See API reference guide

