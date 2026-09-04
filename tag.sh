#!/usr/bin/env bash
set -euo pipefail
TAG_VERSION=v2.10.0-rc.2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Release-hygiene gate: refuses to cut a GA-shaped tag (e.g. v2.9.2, as
# opposed to v2.9.2-rc.N) while go.mod pins a pre-release dependency version
# that actually ships in the release binary. See scripts/check_ga_release_deps.sh.
"$SCRIPT_DIR/scripts/check_ga_release_deps.sh" "$TAG_VERSION"

#git tag -d $TAG_VERSION || true
#git push origin :$TAG_VERSION || true
git tag $TAG_VERSION
git push origin $TAG_VERSION
