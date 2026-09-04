# template_role_binding_demo

Full-lifecycle smoke test for `keyfactor_template_role_binding`.

## What it covers

- `keyfactor_role` + `keyfactor_template_role_binding` create, import,
  reconcile, drift-check, destroy.

## Known lab constraint

Some Command instances reject **any** template update with `"'Policies'
cannot be empty"` (see `main.tf` header; the same gap surfaced
independently by `certificate_template_demo/`). `apply` may fail here until
that SDK/Command-API-version gap is addressed.

## Variables

| Variable | Default | Description |
|---|---|---|
| `suffix` | `_TF` | Appended to resource names. |
| `template_short_name` | `AnyCA_lab-role` | Existing template short name to bind the demo role to. |

## Running

```sh
make build
make init
make lifecycle
```
