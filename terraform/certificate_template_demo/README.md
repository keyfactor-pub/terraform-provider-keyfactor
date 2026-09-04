# certificate_template_demo

Import + update demo for `keyfactor_certificate_template`. Templates cannot
be created via the Command API; this resource is always **imported**, never
created.

## What it covers

- `data.keyfactor_certificate_template` lookup
- `keyfactor_certificate_template` import + `friendly_name` update (revert)

## Known lab constraint

Some Command instances reject **any** template update with:

```
Error updating template in Keyfactor: 'Policies' cannot be empty
```

This looks like a genuine SDK/Command-API-version gap (`keyfactor-go-client/v3`'s
`UpdateTemplateArg` has no `Policies` field at all). `make lab-update` reports
this as a clear `FAIL`, not a harness crash; surfacing it is the point of
this demo on labs with the gap.

## Variables

| Variable | Default | Description |
|---|---|---|
| `template_short_name` | `AnyCA_lab-role` | Template to import (kfclab default, id 6). |
| `friendly_name_override` | `""` | New friendly_name for the update exercise. |

## Running

```sh
make build
make init
make lab-import-existing TEMPLATE_ID=6
make lab-update
```
