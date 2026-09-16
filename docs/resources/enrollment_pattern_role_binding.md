---
page_title: "Resource keyfactor_enrollment_pattern_role_binding - terraform-provider-keyfactor"
subcategory: ""
description: |-
  Binds a single security role to an enrollment pattern using the "/EnrollmentPatterns" API.
  Use one keyfactor_enrollment_pattern_role_binding resource per (enrollment pattern, role) pair. This resource uses a GET-modify-PUT-verify retry loop to safely manage role membership alongside concurrent bindings on the same pattern.
  ~> Important: Enrollment Patterns and this resource are only available in Keyfactor Command v25.0+
  ~> Concurrency note: Command's enrollment pattern PUT endpoint replaces the full role list atomically at the server; there is no per-role sub-endpoint. This resource uses a GET-modify-PUT-verify retry loop (up to 5 attempts with jittered backoff) to reduce — but not eliminate — the lost-update window when two bindings for the same pattern are applied concurrently. For best results, avoid running more than one terraform apply concurrently against the same enrollment pattern.
---

# Resource keyfactor_enrollment_pattern_role_binding

Binds a single security role to an enrollment pattern using the "/EnrollmentPatterns" API.

Use one `keyfactor_enrollment_pattern_role_binding` resource per (enrollment pattern, role) pair. This resource uses a GET-modify-PUT-verify retry loop to safely manage role membership alongside concurrent bindings on the same pattern.

~> **Important:** Enrollment Patterns and this resource are only available in Keyfactor Command v25.0+

~> **Concurrency note:** Command's enrollment pattern PUT endpoint replaces the full role list atomically at the server; there is no per-role sub-endpoint. This resource uses a GET-modify-PUT-verify retry loop (up to 5 attempts with jittered backoff) to reduce — but not eliminate — the lost-update window when two bindings for the same pattern are applied concurrently. For best results, avoid running more than one `terraform apply` concurrently against the same enrollment pattern.

## Example Usage

```terraform
resource "keyfactor_enrollment_pattern_role_binding" "example" {
  enrollment_pattern_name = "Web Server Pattern"
  role_name               = "WebServerTerraformer"
}

import {
  to = keyfactor_enrollment_pattern_role_binding.example
  id = "Web Server Pattern//WebServerTerraformer"
}
```

## Authoritative vs. non-authoritative role management

`keyfactor_enrollment_pattern_role_binding` is the **non-authoritative** resource for
enrollment pattern role membership (analogous to GCP's `google_project_iam_member`). It adds
or removes exactly one `(pattern, role)` pair without touching any other roles on the pattern.

The `keyfactor_enrollment_pattern` resource also exposes `associated_role_names`, an
**authoritative** attribute (analogous to GCP's `google_project_iam_binding`) that replaces
the pattern's entire role list on every apply. **Never mix both mechanisms on the same
enrollment pattern** — a subsequent apply of the `keyfactor_enrollment_pattern` resource will
replace the full role list and remove any roles your `role_binding` resources added.

### When to use this resource (`role_binding`)

Use `keyfactor_enrollment_pattern_role_binding` when **multiple independent Terraform configs
or workspaces** each manage their own role on a shared pattern, and no single config owns the
complete role list.

### When to use `associated_role_names` instead

Use `associated_role_names` on `keyfactor_enrollment_pattern` when a **single Terraform config
owns the complete role list** and should replace it authoritatively on every apply.

### Bootstrap pattern

When `use_ad_permissions = false`, Command requires at least one role at pattern-create time.
The recommended approach:

1. Declare `associated_role_names` on the `keyfactor_enrollment_pattern` resource with the
   initial (bootstrap) role.
2. Add `lifecycle { ignore_changes = [associated_role_names] }` on the pattern resource so
   subsequent applies do not replace the role list.
3. Manage all additional roles via separate `keyfactor_enrollment_pattern_role_binding`
   resources.

```terraform
resource "keyfactor_enrollment_pattern" "example" {
  name               = "My Pattern"
  template_id        = data.keyfactor_certificate_template.t.id
  use_ad_permissions = false
  # Bootstrap with one role (required on create).
  associated_role_names = ["BootstrapRole"]

  lifecycle {
    # Hand off role management to role_binding resources after initial create.
    ignore_changes = [associated_role_names]
  }
}

resource "keyfactor_enrollment_pattern_role_binding" "team_a" {
  enrollment_pattern_name = keyfactor_enrollment_pattern.example.name
  role_name               = "TeamA-Role"
}
```

### Shared-binding caution

This resource does not prevent two independent configs from claiming the same
`(pattern, role)` pair. If both do, a `terraform destroy` from **either** config removes
the role from the pattern for **both** — the surviving config's next `terraform plan` will
show the binding needs recreation. Each `role_binding` should reference a role that only one
config owns. See the [Collection-scoped RBAC walkthrough](../guides/rbac_collection_scoped_access.md)
for a full example and design guidance.

### Drift detection

If the role is removed from the enrollment pattern out-of-band (e.g., by another tool or by
an authoritative `associated_role_names` apply), this resource's next `terraform plan` will
show the binding needs to be recreated — it will not error.

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `enrollment_pattern_name` (String) Name of the enrollment pattern to bind the role to. Changing this value forces a new resource.
- `role_name` (String) Name of the security role to bind. Changing this value forces a new resource.

### Read-Only

- `id` (String) Composite key "<enrollment_pattern_name>//<role_name>", stable across imports.

## Import

Import is supported using the following syntax:

```shell
terraform import keyfactor_enrollment_pattern_role_binding.example "PatternName//RoleName"
```

Or using an HCL import block:

```terraform
import {
  to = keyfactor_enrollment_pattern_role_binding.example
  id = "PatternName//RoleName"
}
```
