---
page_title: "Collection-scoped RBAC walkthrough"
subcategory: ""
description: |-
  A worked, end-to-end example wiring a certificate collection, a collection-scoped security role, an OAuth claim, and an enrollment pattern together.
---

# Collection-scoped RBAC walkthrough

This guide walks through the full chain practitioners most often need to wire up together:
a **certificate collection** → a **security role** whose permissions are scoped to that
collection → an **OAuth claim** identifying a caller (a user, group, or OIDC/Entra service
principal) → a **role/claim association** binding the two → an **enrollment pattern** that
only the role's holders can use.

Each step is a separate resource, so multiple teams/workspaces can compose these
independently without stepping on each other's configuration.

## 1. Certificate collection

Scope everything downstream to a single collection of certificates.

```terraform
resource "keyfactor_certificate_collection" "app_a" {
  name  = "AppA Certificates"
  query = "CN -eq \"appa.example.com\""
}
```

## 2. Security role with collection-scoped permissions

Grant only the permissions this application actually needs, scoped to the collection's ID
(`keyfactor_certificate_collection.app_a.id`) rather than granting collection-wide access.
See [`keyfactor_oauth_security_role`](../resources/oauth_security_role.md) for the full
permission string reference.

```terraform
data "keyfactor_permission_set" "global_permission_set" {
  name = "Global"
}

resource "keyfactor_oauth_security_role" "app_a_role" {
  name              = "AppA-Role"
  description       = "Collection-scoped access for AppA's service principal"
  permission_set_id = data.keyfactor_permission_set.global_permission_set.id
  permissions = [
    "/certificates/collections/read/${keyfactor_certificate_collection.app_a.id}/",
    "/certificates/collections/private_key/read/${keyfactor_certificate_collection.app_a.id}/",
  ]
}
```

~> **Replace, not additive:** every apply sends this full `permissions` set to Command and
replaces whatever is there server-side. See the attribute's own documentation for detail.

## 3. OAuth claim identifying the caller

The claim ties an external identity (an Entra service principal, in this example) to
Command. `claim_type` takes the string form of Command's `CSSCMSCoreEnumsClaimType` enum --
see [`keyfactor_oauth_security_claim`](../resources/oauth_security_claim.md) for the full
value mapping.

```terraform
resource "keyfactor_oauth_security_claim" "app_a_claim" {
  description                    = "Entra service principal - AppA"
  claim_type                     = "OAuthSubject"
  claim_value                    = "<service-principal-object-id>"
  provider_authentication_scheme = "entra_ent_prod"
}
```

## 4. Bind the claim to the role

[`keyfactor_oauth_security_role_claim_association`](../resources/oauth_security_role_claim_association.md)
is a separate join resource -- one per `(role_id, claim_id)` pair -- rather than a list
attribute on either side, specifically so that binding one more claim to a shared role
never touches another team's binding to the same role.

```terraform
resource "keyfactor_oauth_security_role_claim_association" "app_a_binding" {
  role_id  = keyfactor_oauth_security_role.app_a_role.id
  claim_id = keyfactor_oauth_security_claim.app_a_claim.id
}
```

## 5. Enrollment pattern restricted to the role

Finally, restrict an enrollment pattern to holders of `app_a_role` so only identities with
that role (and therefore that claim) can enroll against it.

Command requires at least one role when `use_ad_permissions = false`, so bootstrap the
pattern with the role in `associated_role_names`. The `lifecycle { ignore_changes }` block
hands off ongoing role management to the separate `keyfactor_enrollment_pattern_role_binding`
resource in step 6  after the first apply, subsequent applies will not touch the role list
even if the role reference changes.

```terraform
data "keyfactor_certificate_template" "app_a_template" {
  identifier = "WebServer"
}

resource "keyfactor_enrollment_pattern" "app_a_pattern" {
  name        = "AppA Enrollment Pattern"
  template_id = data.keyfactor_certificate_template.app_a_template.id

  use_ad_permissions    = false
  associated_role_names = [keyfactor_oauth_security_role.app_a_role.name]

  lifecycle {
    ignore_changes = [associated_role_names]
  }
}
```

## 6. Bind the role to the enrollment pattern

[`keyfactor_enrollment_pattern_role_binding`](../resources/enrollment_pattern_role_binding.md)
is a separate join resource -- one per `(enrollment_pattern_name, role_name)` pair --
mirroring exactly the shape of `keyfactor_oauth_security_role_claim_association` in step 4.
Because each binding is its own resource, multiple workspaces can independently add or
remove roles on the *same* shared enrollment pattern without clobbering each other: the
provider's GET-modify-PUT-verify retry loop makes concurrent creates and deletes safe.

```terraform
resource "keyfactor_enrollment_pattern_role_binding" "app_a_binding" {
  enrollment_pattern_name = keyfactor_enrollment_pattern.app_a_pattern.name
  role_name               = keyfactor_oauth_security_role.app_a_role.name
}
```

The binding is importable by composite key `"<pattern_name>//<role_name>"`:

```shell
terraform import keyfactor_enrollment_pattern_role_binding.app_a_binding \
  "AppA Enrollment Pattern//AppA-Role"
```

## Role management: authoritative vs. non-authoritative

The provider exposes two separate mechanisms for enrolling roles on a pattern. Choose one
approach per pattern  mixing both on the same pattern leads to the authoritative resource
replacing the binding-managed roles on every apply.

| Mechanism | Behaviour |
|---|---|
| `associated_role_names` on `keyfactor_enrollment_pattern` | **Authoritative**  every apply sends the declared list to Command and replaces whatever is there server-side. |
| `keyfactor_enrollment_pattern_role_binding` | **Non-authoritative / additive**  each binding resource independently adds or removes exactly one role without touching the rest of the list. |

### When to use `associated_role_names` (authoritative)

Use `associated_role_names` when a **single Terraform config owns the complete role list**
for the pattern. Every `terraform apply` replaces the server-side list with exactly what is
declared.

```terraform
resource "keyfactor_enrollment_pattern" "single_owner" {
  name               = "AppA Enrollment Pattern"
  template_id        = data.keyfactor_certificate_template.t.id
  use_ad_permissions = false
  associated_role_names = [
    keyfactor_oauth_security_role.app_a_role.name,
    keyfactor_oauth_security_role.app_b_role.name,
  ]
}
```

### When to use `keyfactor_enrollment_pattern_role_binding` (non-authoritative)

Use `keyfactor_enrollment_pattern_role_binding` when **multiple independent Terraform configs
or workspaces** each manage their own role on a shared pattern. Each binding resource is
safe to apply and destroy without knowing or touching the roles other configs have added.

```terraform
# Workspace A (owns app_a_role binding only)
resource "keyfactor_enrollment_pattern_role_binding" "app_a" {
  enrollment_pattern_name = "Shared Enrollment Pattern"
  role_name               = "AppA-Role"
}

# Workspace B (owns app_b_role binding only -- independent apply/destroy)
resource "keyfactor_enrollment_pattern_role_binding" "app_b" {
  enrollment_pattern_name = "Shared Enrollment Pattern"
  role_name               = "AppB-Role"
}
```

### Bootstrap pattern (this guide's approach)

When `use_ad_permissions = false`, Command requires at least one role at create time. The
recommended bootstrap pattern:

1. Declare `associated_role_names` on the `keyfactor_enrollment_pattern` resource with the
   initial role (one your config already owns).
2. Add `lifecycle { ignore_changes = [associated_role_names] }` so subsequent applies do not
   touch the list.
3. Manage all additional roles via separate `keyfactor_enrollment_pattern_role_binding`
   resources.

This is the pattern shown in steps 5–6 above.

### Shared-binding caution

`keyfactor_enrollment_pattern_role_binding` does not prevent two independent configs from
claiming the same `(pattern, role)` pair. If both do:

- A `terraform destroy` from **either** config removes the role from the pattern for **both**.
- The surviving config's next `terraform plan` will show the binding needs recreation.

Each `role_binding` should reference a role that only **one** config owns. If a role is
shared across independent configs, prefer `associated_role_names` with authoritative
ownership in a single config.

## Summary

```
keyfactor_certificate_collection
        |
        v  (collection ID scopes the role's permissions)
keyfactor_oauth_security_role  <---- keyfactor_oauth_security_role_claim_association ----  keyfactor_oauth_security_claim
        |
        v  (role name used in the binding resource)
keyfactor_enrollment_pattern_role_binding
        |
        v  (enrollment_pattern_name references the pattern)
keyfactor_enrollment_pattern
```
