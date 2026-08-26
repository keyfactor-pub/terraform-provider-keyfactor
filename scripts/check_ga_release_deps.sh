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
# Beyond the explicit -rc./-alpha./-beta. suffix check, two additional
# GA-only gates guard against ways an unreleased dependency can slip past
# that regex entirely:
#
#   1. Go pseudo-versions (e.g. v0.0.0-20240101000000-abcdef123456), which
#      `go list -deps` reports whenever go.mod pins an untagged commit
#      instead of a real semver tag. These don't match the -rc./-alpha./
#      -beta. suffix pattern at all, so without a dedicated check they
#      silently pass -- including in CI on a fresh checkout, since CI runs
#      this identical script and has no independent way to tell a
#      pseudo-version from any other version string.
#
#      This check is scoped to this project's own first-party Keyfactor
#      dependencies (github.com/Keyfactor/* and the go-pkcs12 fork at
#      github.com/spbsoluble/go-pkcs12 -- see vendor_dev.sh) rather than
#      every dependency in the build closure. Verified against this repo's
#      actual go.mod: several third-party transitive dependencies this
#      project has no control over (e.g. github.com/pkg/browser, pulled in
#      via Azure SDK auth; github.com/youmark/pkcs8, pulled in via
#      keyfactor-go-client) are themselves pinned at upstream pseudo-versions
#      because upstream never tagged those commits, and realistically never
#      will. An unscoped check would permanently and unfixably block every
#      GA tag over dependencies nobody on this project can bump to a "real"
#      tag -- exactly the false-block failure mode the build-closure-instead
#      -of-go.mod-text design above already exists to avoid. Scoping to
#      Keyfactor's own modules keeps the check targeted at what it's
#      actually meant to catch: an untagged commit of one of THIS org's own
#      SDKs (which this team fully controls and does tag) slipping into a
#      release.
#   2. Any `replace` directive in go.mod. A local/relative-path replace
#      resolves `go list -deps`'s reported version to a synthetic
#      placeholder (v0.0.0-00010101000000-000000000000 after `go mod tidy`)
#      or to the original unreplaced `require` version -- either of which
#      can also dodge the pre-release-suffix and pseudo-version checks,
#      and will silently succeed on CI if the replace target path happens
#      to exist identically there (e.g. a path inside the repo itself). A
#      GA release should never ship with ANY replace directive present, so
#      this gate fails closed on that alone rather than trying to classify
#      "safe" vs "unsafe" replace targets. (A replace pointing at an
#      external absolute path that doesn't exist on CI already causes
#      `go list -deps` to fail hard, which is already treated as a gate
#      failure below -- that path is unaffected by this addition.)
#
# Usage:
#   scripts/check_ga_release_deps.sh <version>
#     <version> may be given with or without a leading "v"
#     (e.g. "2.9.2", "v2.9.2", "v2.9.2-rc.1").
#
# Exit status:
#   0 - version is not GA-shaped (pre-release provider tag), or go.mod's
#       shipped build closure has no pre-release dependency pins, no
#       untagged pseudo-version pins of a first-party Keyfactor dependency,
#       and no replace directives.
#   1 - version is GA-shaped AND at least one of the above three gates
#       failed.
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

# Gate 2: Go pseudo-versions (untagged-commit pins) of this project's OWN
# first-party Keyfactor dependencies specifically -- NOT every dependency in
# the build closure. See the scoping rationale in the header comment: many
# third-party transitive dependencies this project doesn't control are
# legitimately, permanently pinned at upstream pseudo-versions, and an
# unscoped check would permanently block every GA tag over those.
#
# The timestamp+hash suffix shape is always "<14-digit UTC timestamp>-<12
# hex char commit>", but the character immediately before the timestamp
# differs by which of the three pseudo-version forms go.mod ended up with:
# a literal "-" for the "no known base version" form (vX.0.0-yyyymmddhhmmss
# -hash), or a "." for the "release base" / "prerelease base" forms
# (vX.Y.(Z+1)-0.yyyymmddhhmmss-hash / vX.Y.Z-pre.0.yyyymmddhhmmss-hash) --
# hence "[.-]" rather than a bare "-" below. This also happens to catch the
# synthetic placeholder a local replace can leave behind after `go mod
# tidy` (v0.0.0-00010101000000-000000000000), since that's shaped
# identically to the no-base-version form.
pseudoversion_offenders="$(printf '%s\n' "$DEPS_OUTPUT" | grep -E '^(github\.com/Keyfactor/\S+|github\.com/spbsoluble/go-pkcs12) \S*[.-][0-9]{14}-[0-9a-f]{12}$' | sort -u || true)"

if [ -n "$pseudoversion_offenders" ]; then
    echo "check-ga-deps: refusing to cut GA tag v$VERSION_NO_V — the release build pins an untagged pseudo-version of a first-party Keyfactor dependency in go.mod:" >&2
    printf '%s\n' "$pseudoversion_offenders" | sed 's/^/    /' >&2
    echo "" >&2
    echo "  Fix: bump the offending module(s) to a real tagged (GA) version in $REPO_ROOT/go.mod," >&2
    echo "  then run 'go mod tidy && ./vendor_dev.sh' (or 'make vendor-dev') and re-run this check." >&2
    exit 1
fi

# Gate 3: any `replace` directive at all. A local/relative-path replace can
# make `go list -deps` report a version that dodges both gates above (see
# the header comment), and the only fully robust fix is to disallow
# shipping a GA tag with a replace directive present at all -- regardless
# of what it points to. `go list -m -f` (rather than a hand-rolled grep of
# go.mod's require/replace syntax, which also supports a multi-line
# `replace (...)` block form) is used here to stay consistent with how the
# rest of this script already asks the Go toolchain for ground truth
# instead of re-parsing go.mod text.
REPLACE_OUTPUT="$(cd "$REPO_ROOT" && go list -m -f '{{if .Replace}}{{.Path}} => {{.Replace}}{{end}}' all 2>&1)" || {
    echo "check-ga-deps: 'go list -m all' failed — cannot verify replace directives, refusing to proceed:" >&2
    echo "$REPLACE_OUTPUT" >&2
    exit 2
}
replace_offenders="$(printf '%s\n' "$REPLACE_OUTPUT" | grep -v '^\s*$' || true)"

if [ -n "$replace_offenders" ]; then
    echo "check-ga-deps: refusing to cut GA tag v$VERSION_NO_V — go.mod contains a replace directive:" >&2
    printf '%s\n' "$replace_offenders" | sed 's/^/    /' >&2
    echo "" >&2
    echo "  A GA release must not ship with any 'replace' directive in go.mod, regardless of its target" >&2
    echo "  (local dev paths don't exist on end-user machines building from source; even a target that" >&2
    echo "  happens to resolve on CI would be shipping unreviewed/untagged code)." >&2
    echo "  Fix: remove the replace directive(s) from $REPO_ROOT/go.mod, run 'go mod tidy && ./vendor_dev.sh'" >&2
    echo "  (or 'make vendor-dev'), and re-run this check." >&2
    exit 1
fi

echo "check-ga-deps: v$VERSION_NO_V is GA-shaped and the release build has no pre-release dependency pins, no pseudo-version pins, and no replace directives. OK." >&2
exit 0
