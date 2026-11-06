#!/bin/bash
# gen-terraformrc.sh <provider-bin-dir> <rc-file>
#
# Writes the dev_overrides CLI config used by PROVIDER_MODE=dev, pointing at a
# PER-WORKTREE provider binary directory (terraform/.provider-bin) instead of
# the shared ~/go/bin, so a run can never silently execute another worktree's
# build. Called at make-parse time from demo-common.mk; idempotent (the file is
# only rewritten when its content would change) and prints nothing.
set -eu
bin=$1
rc=$2
want=$(printf 'provider_installation {\n  dev_overrides {\n    "keyfactor-pub/keyfactor" = "%s"\n  }\n  direct {}\n}\n' "$bin")
if [ -f "$rc" ] && [ "$(cat "$rc")" = "$want" ]; then exit 0; fi
mkdir -p "$bin"
umask 077
printf '%s\n' "$want" > "$rc.tmp.$$"
mv "$rc.tmp.$$" "$rc"
