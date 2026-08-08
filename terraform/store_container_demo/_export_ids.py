#!/usr/bin/env python3
"""Extract keyfactor_certificate_store id pairs from terraform show -json output."""
import json, sys, os

state_file = os.path.join(os.path.dirname(__file__), "tf_state.json")
with open(state_file) as f:
    state = json.load(f)

pairs = []
for res in state.get("values", {}).get("root_module", {}).get("resources", []):
    # mode must be checked too -- outputs.tf declares a `data
    # "keyfactor_certificate_store" "container_name_style"` read-back data
    # source with the SAME type+name as the managed resource it reads back;
    # without this filter both show up here, producing a duplicate pair
    # that breaks the state-rm/re-import round trip (confirmed 2026-08-08).
    if res.get("type") != "keyfactor_certificate_store" or res.get("mode") != "managed":
        continue
    name = res["name"]
    store_id = res["values"].get("id", "")
    if store_id:
        pairs.append((name, store_id))

out = os.path.join(os.path.dirname(__file__), "_import_pairs.txt")
with open(out, "w") as f:
    for name, sid in pairs:
        f.write(f"{name} {sid}\n")

print(f"Saved {len(pairs)} pairs to _import_pairs.txt")
