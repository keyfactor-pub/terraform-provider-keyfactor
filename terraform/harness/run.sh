#!/bin/bash
# run.sh <demo>
#
# Quiet wrapper around `make <demo>-lifecycle`: same behaviour, same exit code,
# but the full output goes to a log file and only a compact, secret-redacted
# summary reaches stdout. Invoked by `make <demo>-run`, `make harness` and
# `make harness-run` (terraform/GNUmakefile); see harness/README.md.
#
# Environment (all optional):
#   HARNESS_MODE          PROVIDER_MODE to run with (dev|registry; default registry)
#   HARNESS_SUFFIX        SUFFIX in effect (recorded in the summary only; a
#                         SUFFIX given on the make command line already
#                         reaches the demo through MAKEFLAGS)
#   HARNESS_MAKE          make binary (default: make)
#   HARNESS_VERBOSE=1     also stream the full output to stdout (legacy
#                         `make harness` behaviour) and print only a one-line
#                         verdict plus paths afterwards
#   HARNESS_LOG_DIR       log/summary dir (default terraform/.harness-logs, mode 700)
#   HARNESS_RESULTS_JSONL one-line-per-run file (default terraform/harness-results.jsonl)
#   HARNESS_RESULTS_TXT   append a "demo,STATUS,detail" CSV line here
#   DRIFT_FAIL=1          exit 3 when the lifecycle passed but a plan showed
#                         unexpected (non-allowlisted) changes (status DRIFT)
#   KEYFACTOR_ENV_FILE    env file whose secret-looking values are scrubbed
#                         from anything printed (default ~/.env_kfclab)
#
# Quiet flags exported to terraform (each verified against `terraform <cmd>
# -help` on 1.17): TF_IN_AUTOMATION=1; -no-color and -input=false everywhere
# they exist; -compact-warnings on plan/apply/destroy. They are injected with
# TF_CLI_ARGS_<cmd>, so no makefile edit is needed and an explicit -no-color
# in a recipe is harmless.
#
# Exit code: the lifecycle's own exit code; 130/143 when interrupted;
# 3 for DRIFT under DRIFT_FAIL=1.
umask 077
demo=${1:?usage: run.sh <demo>}
HERE=$(cd "$(dirname "$0")" && pwd)
TFDIR=$(dirname "$HERE")
WORKTREE=$(cd "$TFDIR/.." && pwd)
MAKE_BIN=${HARNESS_MAKE:-make}
mode=${HARNESS_MODE:-registry}
suffix=${HARNESS_SUFFIX:-_TF}
verbose=${HARNESS_VERBOSE:-0}
envfile=${KEYFACTOR_ENV_FILE:-$HOME/.env_kfclab}

logdir=${HARNESS_LOG_DIR:-$TFDIR/.harness-logs}
results_jsonl=${HARNESS_RESULTS_JSONL:-$TFDIR/harness-results.jsonl}
mkdir -p "$logdir"
chmod 700 "$logdir"
ts=$(date -u +%Y%m%dT%H%M%SZ)
log=$logdir/$demo-$ts.log
sumfile=$logdir/$demo-$ts.summary.json
: > "$log"

tmpdir=$(mktemp -d)
vals=$tmpdir/redact-values
fifo=$tmpdir/out.fifo
trap 'rm -rf "$tmpdir"' EXIT

# Literal secret values from the env file (never printed) for the redactor.
# shellcheck disable=SC1090
( set -a; [ -r "$envfile" ] && . "$envfile" >/dev/null 2>&1; set +a
  env | grep -E '^[A-Za-z0-9_]*(SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE_KEY|API_KEY)[A-Za-z0-9_]*=' | sed 's/^[^=]*=//'
) > "$vals" 2>/dev/null
chmod 600 "$vals"
export HARNESS_REDACT_VALUES_FILE=$vals

export TF_IN_AUTOMATION=1
export TF_CLI_ARGS_init="-no-color -input=false"
export TF_CLI_ARGS_validate="-no-color"
export TF_CLI_ARGS_plan="-no-color -compact-warnings -input=false"
export TF_CLI_ARGS_apply="-no-color -compact-warnings -input=false"
export TF_CLI_ARGS_destroy="-no-color -compact-warnings -input=false"
export TF_CLI_ARGS_import="-no-color -input=false"
export TF_CLI_ARGS_show="-no-color"
export TF_CLI_ARGS_output="-no-color"

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
t0=$(date +%s)

mkfifo "$fifo"
# tee ignores INT so a Ctrl-C still lets it flush the log (make gets the signal)
if [ "$verbose" = "1" ]; then ( trap "" INT; exec tee "$log" < "$fifo" ) & else ( trap "" INT; exec tee "$log" < "$fifo" > /dev/null ) & fi
teepid=$!
"$MAKE_BIN" --no-print-directory -C "$TFDIR" "$demo-lifecycle" PROVIDER_MODE="$mode" > "$fifo" 2>&1 &
pid=$!

interrupted=0
on_signal() { interrupted=$1; kill -TERM "$pid" 2>/dev/null; }
trap 'on_signal 130' INT
trap 'on_signal 143' TERM HUP
rc=0
while true; do
  wait "$pid"; rc=$?
  kill -0 "$pid" 2>/dev/null || break
done
wait "$teepid" 2>/dev/null
[ "$interrupted" != "0" ] && rc=$interrupted
trap - INT TERM HUP

t1=$(date +%s)
dur=$((t1 - t0))

# Tighten any state/plan artifacts the run left in the demo dir (belt and
# braces on top of umask 077 in demo-common.mk; also fixes files from old runs).
chmod -f 600 "$TFDIR/$demo"/tf_state.json "$TFDIR/$demo"/terraform.tfstate* "$TFDIR/$demo"/*.tfplan "$TFDIR/$demo"/tfplan* 2>/dev/null

allow=()
[ -r "$TFDIR/$demo/drift-allowlist.txt" ] && allow=(--allowlist "$TFDIR/$demo/drift-allowlist.txt")
parsed=$("$HERE/parse-log.pl" "${allow[@]}" "$log")
if [ -z "$parsed" ]; then parsed='{"log_lines":0,"steps":[],"plans":{"total":0,"clean":0,"with_changes":0},"failed":null,"errors":[],"warnings":{},"plain_errors":["parse-log.pl failed"],"harness_fail":[],"skipped":null,"auth_preflight":null,"provider":{},"cleanup":null,"drift":[],"drift_allowed":[],"allowlist":{"rejected":[]}}'; fi

head=$(git -C "$WORKTREE" rev-parse --short HEAD 2>/dev/null || echo unknown)
dirty=false
git -C "$WORKTREE" diff --quiet HEAD 2>/dev/null || dirty=true
provider_bin=$TFDIR/.provider-bin/terraform-provider-keyfactor
prov_sha=""
[ "$mode" = "dev" ] && [ -f "$provider_bin" ] && prov_sha=$(shasum -a 256 "$provider_bin" | cut -c1-12)

jq -n --argjson p "$parsed" \
  --arg demo "$demo" --arg mode "$mode" --arg suffix "$suffix" \
  --arg worktree "$WORKTREE" --arg head "$head" --argjson dirty "$dirty" \
  --arg started "$started" --argjson dur "$dur" --argjson rc "$rc" \
  --argjson interrupted "$interrupted" --arg log "$log" --arg sumfile "$sumfile" \
  --arg provbin "$provider_bin" --arg provsha "$prov_sha" \
  --argjson driftfail "$([ "${DRIFT_FAIL:-0}" = "1" ] && echo true || echo false)" '
  $p
  | .provider |= (if (.path // "") == "" and $mode == "dev" then {path: $provbin, sha256: $provsha}
                  elif .sha256 == null and $provsha != "" then . + {sha256: $provsha} else . end)
  | . + {
      schema: "kf-harness-summary/v1",
      demo: $demo, mode: $mode, suffix: $suffix, worktree: $worktree,
      head: $head, dirty: $dirty,
      started_utc: $started, duration_s: $dur,
      exit_code: $rc, interrupted: ($interrupted != 0),
      drift_fail_enabled: $driftfail,
      log: $log, summary: $sumfile,
      status: (
        if $interrupted != 0 then "INTERRUPTED"
        elif $rc != 0 and .auth_preflight != null then "AUTH_PREFLIGHT_FAIL"
        elif $rc != 0 then "FAIL"
        elif .skipped != null then "SKIP"
        elif (.drift | length) > 0 then "DRIFT"
        else "PASS" end)
    }
  | .failed_step = (.failed.step // null)
' > "$sumfile"

status=$(jq -r .status "$sumfile")

# One compact line per run for trend/triage tooling (gitignored).
jq -c '{schema, demo, status, exit_code, started_utc, duration_s, mode, suffix, head, dirty,
        provider_sha256: .provider.sha256, failed_step, failed_phase: .failed.phase,
        errors: [.errors[] | select(.cleanup | not) | .summary], plans,
        drift: (.drift | length), drift_allowed: (.drift_allowed | length),
        cleanup, log, summary}' "$sumfile" >> "$results_jsonl"

case $status in
    SKIP)  detail=$(jq -r '.skipped // ""' "$sumfile" | head -1 | sed 's/,/;/g') ;;
    FAIL)  detail="exit $rc" ;;
    DRIFT) detail="$(jq -r '.drift | length' "$sumfile") drifting plan step(s)" ;;
    *)     detail=$(jq -r 'if .status == "PASS" then "" else .status end' "$sumfile") ;;
  esac
if [ -n "${HARNESS_RESULTS_TXT:-}" ]; then echo "$demo,$status,$detail" >> "$HARNESS_RESULTS_TXT"; fi

if [ "$verbose" = "1" ]; then
  echo ">>> $demo: $status${detail:+ ($detail)}"
  echo "    log: $log"
  echo "    summary: $sumfile"
else
  "$HERE/format-summary.sh" "$sumfile" | "$HERE/redact.pl"
fi

if [ "$status" = "DRIFT" ] && [ "${DRIFT_FAIL:-0}" = "1" ]; then exit 3; fi
exit "$rc"
