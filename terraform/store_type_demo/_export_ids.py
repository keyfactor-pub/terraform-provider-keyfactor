#!/usr/bin/env python3
"""Read tf_state.json and write _import_pairs.txt (name id short_name per line)."""
import json

with open('tf_state.json') as f:
    state = json.load(f)

resources = state.get('values', {}).get('root_module', {}).get('resources', [])
pairs = [
    (r['name'], r['values']['id'], r['values']['short_name'])
    for r in resources
    if r['type'] == 'keyfactor_certificate_store_type' and r.get('mode') == 'managed'
]
with open('_import_pairs.txt', 'w') as f:
    for name, rid, sn in sorted(pairs):
        f.write(f"{name} {rid} {sn}\n")

print(f"Saved {len(pairs)} pairs to _import_pairs.txt")
