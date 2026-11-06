#!/bin/bash
# format-summary.sh <summary.json>
#
# Renders the compact stdout report for one run: ~8 lines on a green run,
# <= ~50 lines on a red one (failing step, error blocks, log line range).
# Pure jq (format-summary.jq) over the summary JSON; run.sh pipes the result
# through redact.pl before printing, and error detail is already redacted
# when parse-log.pl extracts it.
set -eu
exec jq -r -f "$(dirname "$0")/format-summary.jq" "$1"
