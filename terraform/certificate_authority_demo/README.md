# certificate_authority_demo

Import/read smoke test for `keyfactor_certificate_authority`. Deliberately
**import-only**, with `lifecycle { prevent_destroy = true }`; this demo never
creates, updates, or destroys a CA connection; it targets the lab's real,
already-configured "OpenBao PKI" CA (id 2).

## What it covers

- `keyfactor_certificate_authority` import + drift-check against a real,
  shared CA connection (never mutated).

## Variables

| Variable | Default | Description |
|---|---|---|
| `logical_name` | `OpenBao PKI` | Logical name of the lab CA to import. |
| `host_name` | `https://gateway-gateway-openbao.lab.local/AnyGatewayREST/ejbca` | Host of the lab CA to import. |
| `ca_type` | `1` | 0=DCOM, 1=HTTPS/AnyCA REST Gateway. |

## Running

```sh
make build
make init
make lab-import-existing CA_ID=2
make lab-drift-check
```

`make apply` / `make destroy` are intentionally disabled; see `GNUmakefile`.
