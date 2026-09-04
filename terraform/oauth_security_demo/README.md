# oauth_security_demo

End-to-end lifecycle of the OAuth security resources: role, claim, and their
association.

## What it covers

- `keyfactor_oauth_security_role`
- `keyfactor_oauth_security_claim`
- `keyfactor_oauth_security_role_claim_association`
- `data.keyfactor_permission_set`, `data.keyfactor_oauth_security_role`,
  `data.keyfactor_oauth_security_claim` readback

## Variables

See `variables.tf` — `suffix`, `claim_value`, `role_description`,
`claim_description`.

## Running

```sh
make build
make init
make lifecycle
```
