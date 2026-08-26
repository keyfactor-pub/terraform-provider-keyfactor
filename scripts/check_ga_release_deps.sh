#!/usr/bin/env bash
# check_ga_release_deps.sh — release-hygiene gate.
#
# Refuses to let a GA-shaped provider tag (e.g. v2.9.2) be cut while go.mod
# pins a pre-release (-rc./-alpha./-beta.) version of any dependency that is
# actually compiled into the released provider binary.
#
# Why "actually compiled in": go.mod's require block includes test-only
# tooling (e.g. the VCR cassette library used only by _test.go files), which
# can pin its own pre-release transitive deps that this project has no
# control over and that never ship in the release artifact. Gating on the
# full go.mod text would produce a permanent, unfixable false block. Instead
# this script computes the actual build closure of the `main` package (which
# excludes _test.go-only imports) via `go list -deps` and checks only that.
#
# Pre-release provider tags (vX.Y.Z-rc.N, -beta.N, -alpha.N) are exempt:
# an RC build pinning RC dependencies is expected and fine.
#
# Usage:
#   scripts/check_ga_release_deps.sh <version>
#     <version> may be given with or without a leading "v"
#     (e.g. "2.9.2", "v2.9.2", "v2.9.2-rc.1").
#
# Exit status:
#   0 - version is not GA-shaped (pre-release provider tag), or go.mod's
#       shipped build closure has no pre-release dependency pins.
#   1 - version is GA-shaped AND at least one dependency actually compiled
#       into the release binary is pinned to a pre-release version.
#   2 - usage/environment error (couldn't determine the answer either way).

set -euo pipefail

VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    echo "usage: $0 <version>" >&2
    echo "  e.g.: $0 2.9.2       # GA-shaped, will be gated" >&2
    echo "        $0 v2.9.2-rc.1 # pre-release, gate is skipped" >&2
    exit 2
fi

# Strip a leading "v" so both "2.9.2" and "v2.9.2" work.
VERSION_NO_V="${VERSION#v}"

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO_ROOT" ]; then
    echo "check-ga-deps: must be run inside the terraform-provider-keyfactor git checkout" >&2
    exit 2
fi

# A GA-shaped version has no -rc./-alpha./-beta. pre-release suffix, per this
# repo's tag convention (vX.Y.Z GA vs vX.Y.Z-rc.N/-beta.N/-alpha.N pre-release).
if [[ "$VERSION_NO_V" =~ -(rc|alpha|beta)([.].*)?$ ]]; then
    echo "check-ga-deps: '$VERSION_NO_V' is a pre-release provider tag; skipping GA dependency guard (RC/beta/alpha builds pinning RC deps are expected)." >&2
    exit 0
fi

# Compute the module versions actually compiled into the release binary:
# `go list -deps` on the main package excludes anything only reachable via
# _test.go files (e.g. the VCR test-cassette library and its own deps),
# unlike a raw grep of go.mod's require block.
DEPS_OUTPUT="$(cd "$REPO_ROOT" && go list -deps -f '{{with .Module}}{{.Path}} {{.Version}}{{end}}' . 2>&1)" || {
    echo "check-ga-deps: 'go list -deps' failed — cannot verify dependency versions, refusing to proceed:" >&2
    echo "$DEPS_OUTPUT" >&2
    exit 2
}

# Match semver pre-release identifiers: -rc.<n>, -alpha.<n>, -beta.<n>.
offenders="$(printf '%s\n' "$DEPS_OUTPUT" | grep -E '^\S+ \S*-(rc|alpha|beta)\.[0-9A-Za-z.]+$' | sort -u || true)"

if [ -n "$offenders" ]; then
    echo "check-ga-deps: refusing to cut GA tag v$VERSION_NO_V — the release build pins pre-release dependency version(s) in go.mod:" >&2
    printf '%s\n' "$offenders" | sed 's/^/    /' >&2
    echo "" >&2
    echo "  Fix: bump the offending module(s) to a GA (non -rc./-alpha./-beta.) version in $REPO_ROOT/go.mod," >&2
    echo "  then run 'go mod tidy && ./vendor_dev.sh' (or 'make vendor-dev') and re-run this check." >&2
    exit 1
fi

echo "check-ga-deps: v$VERSION_NO_V is GA-shaped and the release build has no pre-release dependency pins. OK." >&2
exit 0
