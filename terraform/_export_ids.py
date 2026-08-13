#!/usr/bin/env python3
"""Shared helper for terraform/*_demo/GNUmakefile `import-all` targets.

Reads tf_state.json (produced by `terraform show -json > tf_state.json` in
the CURRENT directory -- a demo's own directory, since each demo's Makefile
invokes this as `python3 ../_export_ids.py ...` after `cd`-ing there) and
writes _import_pairs.txt with one "<resource_name> <id>" pair per line for
every MANAGED resource of the given Terraform resource type, sorted by name.

Usage: _export_ids.py RESOURCE_TYPE [ID_ATTR]
  RESOURCE_TYPE  Terraform resource type, e.g. keyfactor_application
  ID_ATTR        Attribute in `values` holding the import ID (default: id).
                 e.g. `certificate_id` for keyfactor_certificate.

Consolidates 5 near-identical per-demo copies (application_demo,
certificate_csr_demo, certificate_pfx_demo, k8s_orchestrator_demo,
store_container_demo) that differed only in the hardcoded resource type and
id attribute name -- see full-review round 1 advisory C. The mode=="managed"
filter is now applied unconditionally for all callers: k8s_orchestrator_demo's
original copy lacked it (a latent bug the moment that demo grows a same-type
data source, matching the fix store_container_demo's copy already carried
with its own dated comment).

store_type_demo (3-column output: name id short_name) and
release_validation_demo (2 resource types, 3-column output: type name id)
have a genuinely different output shape their Makefiles' `import-all`
targets rely on and are NOT consolidated here -- see advisory C's review
notes; they keep their own _export_ids.py.
"""
import json
import sys

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print(f"Usage: {sys.argv[0]} RESOURCE_TYPE [ID_ATTR]", file=sys.stderr)
    sys.exit(1)

resource_type = sys.argv[1]
id_attr = sys.argv[2] if len(sys.argv) == 3 else "id"

with open("tf_state.json") as f:
    state = json.load(f)

resources = state.get("values", {}).get("root_module", {}).get("resources", [])
pairs = [
    (r["name"], str(r["values"][id_attr]))
    for r in resources
    if r.get("type") == resource_type and r.get("mode") == "managed" and r.get("values", {}).get(id_attr)
]

with open("_import_pairs.txt", "w") as f:
    for name, rid in sorted(pairs):
        f.write(f"{name} {rid}\n")

print(f"Saved {len(pairs)} pairs to _import_pairs.txt")
