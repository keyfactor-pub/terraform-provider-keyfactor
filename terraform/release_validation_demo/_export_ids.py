#!/usr/bin/env python3
"""Extract resource-address/id pairs from terraform show -json output for
both keyfactor_certificate and keyfactor_certificate_store resources."""
import json
import os

state_file = os.path.join(os.path.dirname(__file__), "tf_state.json")
with open(state_file) as f:
    state = json.load(f)

IMPORTABLE_TYPES = {"keyfactor_certificate", "keyfactor_certificate_store"}

pairs = []
for res in state.get("values", {}).get("root_module", {}).get("resources", []):
    rtype = res.get("type")
    if rtype not in IMPORTABLE_TYPES:
        continue
    name = res["name"]
    values = res.get("values", {})
    rid = values.get("certificate_id") if rtype == "keyfactor_certificate" else values.get("id")
    if rid:
        pairs.append((rtype, name, rid))

out = os.path.join(os.path.dirname(__file__), "_import_pairs.txt")
with open(out, "w") as f:
    for rtype, name, rid in pairs:
        f.write(f"{rtype} {name} {rid}\n")

print(f"Saved {len(pairs)} pairs to _import_pairs.txt")
