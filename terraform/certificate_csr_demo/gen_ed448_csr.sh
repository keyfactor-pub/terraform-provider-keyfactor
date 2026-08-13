#!/usr/bin/env bash
# Generates a stable Ed448 private key and CSR for use with the
# hashicorp/external data source.
#
# The private key is written to .ed448_key.pem once and reused on
# subsequent calls (Ed448 signatures are deterministic per RFC 8032,
# so the same key + subject always produces the same CSR bytes).
#
# Input (stdin): JSON object with {"suffix": "..."}
# Output (stdout): JSON object with {"csr": "<PEM with \\n escaping>"}
#
# Requirements: openssl >= 1.1.1, python3

set -euo pipefail

input=$(cat)
suffix=$(python3 -c "import sys,json; print(json.load(sys.stdin).get('suffix',''))" <<<"$input")
cn="tf-demo-csr-ed448${suffix}.example.com"
keyfile="$(cd "$(dirname "$0")" && pwd)/.ed448_key.pem"

# Generate the private key once; reuse on subsequent calls.
if [ ! -f "$keyfile" ]; then
  openssl genpkey -algorithm ed448 -out "$keyfile" 2>/dev/null
fi

# Generate the CSR (deterministic for Ed448).
csr=$(openssl req -new -key "$keyfile" -subj "/CN=${cn}" 2>/dev/null)

# Emit JSON. python3 handles newline escaping correctly.
python3 -c "import sys, json; print(json.dumps({'csr': sys.argv[1]}))" "$csr"
