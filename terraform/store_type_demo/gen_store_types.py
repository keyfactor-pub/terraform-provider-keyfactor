#!/usr/bin/env python3
"""
Generate keyfactor_certificate_store_type terraform resources from
the state data captured by `terraform show -json`.

Usage:
    terraform show -json > tf_state.json
    python3 gen_store_types.py [--suffix SUFFIX] [--state tf_state.json] [--out store_types.tf]

Defaults:
    suffix  = _TF
    state   = tf_state.json   (relative to script location)
    out     = store_types.tf  (relative to script location)
"""

import argparse
import json
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def b(val):
    return "true" if val else "false"


def tf_id(short_name):
    return re.sub(r"[^a-zA-Z0-9_]", "_", short_name).lower()


def generate(types, suffix):
    lines = []
    for st in types:
        sn = st["short_name"]
        cap = st.get("capability") or ""
        new_sn = sn + suffix
        new_cap = (cap + suffix) if cap else ""
        name = st.get("name", sn)
        rid = tf_id(sn)

        new_name = name + suffix
        lines.append(f'resource "keyfactor_certificate_store_type" "{rid}" {{')
        lines.append(f"  name                    = {json.dumps(new_name)}")
        lines.append(f"  short_name              = {json.dumps(new_sn)}")
        if new_cap:
            lines.append(f"  capability              = {json.dumps(new_cap)}")
        lines.append(f"  local_store             = {b(st['local_store'])}")
        lines.append(f"  store_path_type         = {json.dumps(st.get('store_path_type') or '')}")
        lines.append(f"  store_path_value        = {json.dumps(st.get('store_path_value') or '')}")
        lines.append(f"  private_key_allowed     = {json.dumps(st.get('private_key_allowed') or '')}")
        lines.append(f"  server_required         = {b(st['server_required'])}")
        lines.append(f"  power_shell             = {b(st['power_shell'])}")
        lines.append(f"  blueprint_allowed       = {b(st['blueprint_allowed'])}")
        lines.append(f"  custom_alias_allowed    = {json.dumps(st.get('custom_alias_allowed') or '')}")
        lines.append(f"  supports_add            = {b(st['supports_add'])}")
        lines.append(f"  supports_create         = {b(st['supports_create'])}")
        lines.append(f"  supports_discovery      = {b(st['supports_discovery'])}")
        lines.append(f"  supports_enrollment     = {b(st['supports_enrollment'])}")
        lines.append(f"  supports_remove         = {b(st['supports_remove'])}")
        lines.append(f"  password_entry_supported = {b(st['password_entry_supported'])}")
        lines.append(f"  password_store_required  = {b(st['password_store_required'])}")
        lines.append(f"  password_style          = {json.dumps(st.get('password_style') or '')}")

        props = st.get("properties") or []
        lines.append("  properties = [")
        for p in props:
            lines.append("    {")
            lines.append(f"      name          = {json.dumps(p['name'])}")
            lines.append(f"      display_name  = {json.dumps(p['display_name'])}")
            lines.append(f"      type          = {json.dumps(p['type'])}")
            lines.append(f"      depends_on    = {json.dumps(p.get('depends_on') or '')}")
            lines.append(f"      default_value = {json.dumps(p.get('default_value') or '')}")
            lines.append(f"      required      = {b(p['required'])}")
            lines.append("    },")
        lines.append("  ]")

        eps = st.get("entry_parameters") or []
        lines.append("  entry_parameters = [")
        for ep in eps:
            lines.append("    {")
            lines.append(f"      name                          = {json.dumps(ep['name'])}")
            lines.append(f"      display_name                  = {json.dumps(ep['display_name'])}")
            lines.append(f"      type                          = {json.dumps(ep['type'])}")
            lines.append(f"      depends_on                    = {json.dumps(ep.get('depends_on') or '')}")
            lines.append(f"      default_value                 = {json.dumps(ep.get('default_value') or '')}")
            lines.append(f"      options                       = {json.dumps(ep.get('options') or '')}")
            lines.append(f"      required_when_on_add          = {b(ep['required_when_on_add'])}")
            lines.append(f"      required_when_on_remove       = {b(ep['required_when_on_remove'])}")
            lines.append(f"      required_when_on_reenrollment = {b(ep['required_when_on_reenrollment'])}")
            lines.append(f"      required_when_has_private_key = {b(ep['required_when_has_private_key'])}")
            lines.append("    },")
        lines.append("  ]")

        lines.append("}")
        lines.append("")

    return "\n".join(lines)


# Representative subset (~10) cloned by default -- NOT the full store type
# fleet. Cloning all ~71 store types on every run left 213 orphaned clones in
# earlier iterations of this harness; a small, fixed, well-known set is
# enough to exercise keyfactor_certificate_store_type's schema (properties,
# entry_parameters, capability, etc.) without polluting the lab. Always
# clones from the PRISTINE (unsuffixed) short name, so repeated runs with a
# different --suffix don't stack suffixes onto a previous clone's name.
DEFAULT_REPRESENTATIVE_SHORT_NAMES = [
    "K8SCert", "K8SCluster", "K8SNS", "K8SSecret", "K8STLSSecr", "K8SJKS", "K8SPKCS12",
    "HCVPKI", "HCVKVPEM", "PEM",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suffix", default="_TF", help="Suffix appended to short_name and capability (default: _TF)")
    parser.add_argument("--state", default=os.path.join(SCRIPT_DIR, "tf_state.json"), help="Path to terraform show -json output")
    parser.add_argument("--out", default=os.path.join(SCRIPT_DIR, "store_types.tf"), help="Output .tf file path")
    parser.add_argument(
        "--only",
        default=",".join(DEFAULT_REPRESENTATIVE_SHORT_NAMES),
        help="Comma-separated list of PRISTINE (unsuffixed) short_names to clone. "
        "Default is a representative ~10-type subset, not the full fleet. Pass --only=ALL to clone every type.",
    )
    args = parser.parse_args()

    with open(args.state) as f:
        state = json.load(f)

    resources = state.get("values", {}).get("root_module", {}).get("resources", [])
    types = []
    for r in resources:
        if r.get("address") == "data.keyfactor_certificate_store_types.all":
            types = r["values"]["store_types"]
            break

    if not types:
        print("ERROR: data.keyfactor_certificate_store_types.all not found in state.")
        print("Run: terraform apply && terraform show -json > tf_state.json")
        raise SystemExit(1)

    if args.only != "ALL":
        wanted = {n.strip() for n in args.only.split(",") if n.strip()}
        missing = wanted - {st["short_name"] for st in types}
        if missing:
            print(f"WARNING: requested short_names not found on this Command instance: {sorted(missing)}")
        types = [st for st in types if st["short_name"] in wanted]
        if not types:
            print("ERROR: none of the requested --only short_names were found.")
            raise SystemExit(1)

    content = generate(types, args.suffix)
    with open(args.out, "w") as f:
        f.write(content)

    print(f"Generated {len(types)} resources → {args.out}")


if __name__ == "__main__":
    main()
