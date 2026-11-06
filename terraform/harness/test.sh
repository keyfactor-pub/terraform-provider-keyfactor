#!/bin/bash
# harness/test.sh: OFFLINE tests for the terraform demo harness helpers.
# No lab, no network, no terraform, no credentials. Run: make -C terraform harness-test
#
# Covers: log parser (green / red / drift / secrets fixtures), allowlist rules,
# secret redaction (stdout, summary JSON, redact.pl filter), run.sh end to end
# against a fake `make` (exit-code propagation, DRIFT_FAIL, interrupt handling,
# stdout size), cross-worktree lock, dev .terraformrc generation, cleanup.sh
# logic, and a few makefile invariants (umask, per-worktree provider dir).
#
# Fixtures (fixtures/): green.log and red.log are real recorded demo runs
# (sanitized: paths/hosts rewritten, polling lines dropped); drift.log and
# secrets.log are SYNTHETIC (hand-edited / hand-written, marked on line 1).
HERE=$(cd "$(dirname "$0")" && pwd)
TFDIR=$(dirname "$HERE")
FIX=$HERE/fixtures
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
pass=0
fail=0

ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
bad()  { fail=$((fail + 1)); echo "FAIL - $1"; [ -n "${2:-}" ] && echo "       $2"; }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
jqok() { local d=$1 f=$2 e=$3; if jq -e "$e" "$f" >/dev/null 2>&1; then ok "$d"; else bad "$d" "jq -e '$e' on $f"; fi; }
nogrep() { local d=$1 pat=$2 f=$3; if grep -q -- "$pat" "$f"; then bad "$d" "found '$pat' in $f"; else ok "$d"; fi; }

# ---- fake make for run.sh / cleanup.sh -------------------------------------
cat > "$T/fakemake" <<'EOF'
#!/bin/bash
# FAKE_FIXTURE/FAKE_RC/FAKE_SLEEP drive run.sh tests; STATEFILE/FAKE_* drive cleanup.sh tests.
case " $* " in
  *" state-count "*) cat "$STATEFILE"; exit 0 ;;
  *" -n "*" lab-destroy "*) exit "${FAKE_NO_LABDESTROY:-0}" ;;
  *" lab-destroy "*|*" destroy "*)
    echo "unset X; TF_CLI_CONFIG_FILE=x terraform destroy -auto-approve"
    echo "Destroy complete! Resources: 3 destroyed."
    [ "${FAKE_DESTROY_RC:-0}" = "0" ] && echo 0 > "$STATEFILE"
    exit "${FAKE_DESTROY_RC:-0}" ;;
esac
if [ -n "${FAKE_SLEEP:-}" ]; then echo "starting"; sleep "$FAKE_SLEEP"; fi
[ -n "${FAKE_FIXTURE:-}" ] && cat "$FAKE_FIXTURE"
exit "${FAKE_RC:-0}"
EOF
chmod +x "$T/fakemake"

echo "== parse-log.pl"
"$HERE/parse-log.pl" "$FIX/green.log" > "$T/green.json"
jqok "green: 3 plans all clean, no failure, no drift" "$T/green.json" \
  '.plans == {total:3, clean:3, with_changes:0} and .failed == null and (.drift|length) == 0'
jqok "green: 11 steps, destroy last and destroyed" "$T/green.json" \
  '(.steps|length) == 11 and .steps[-1].cmd == "destroy" and .steps[-1].result == "destroyed"'
jqok "green: phases recovered from echoed make lines" "$T/green.json" \
  '[.steps[]|.phase] | index("drift-check") != null and index("reconcile") != null and index("import-all") != null'
jqok "green: dev-override warning counted, not an error" "$T/green.json" \
  '(.errors|length) == 0 and (.warnings["Provider development overrides are in effect"] // 0) > 0'

"$HERE/parse-log.pl" "$FIX/red.log" > "$T/red.json"
jqok "red: failing step/phase/chain identified" "$T/red.json" \
  '.failed.step == "apply" and .failed.phase == "apply" and ([.failed.chain[].target] == ["apply","lab-apply","k8s_orchestrator_demo-lifecycle"])'
jqok "red: error block resource, location, line range" "$T/red.json" \
  '.errors[0].resource == "keyfactor_certificate.demo" and .errors[0].at == "deployments.tf:9" and .errors[0].log_end > .errors[0].log_line'
jqok "red: error summary captured" "$T/red.json" \
  '.errors[0].summary | startswith("Unable to create Keyfactor Command certificate")'

"$HERE/parse-log.pl" "$FIX/drift.log" > "$T/drift.json"
jqok "drift: plan step with changes -> unexpected drift, attrs parsed" "$T/drift.json" \
  '(.drift|length) == 1 and .drift[0].phase == "drift-check" and ([.drift[0].changes[].address] | length) == 2 and (.drift[0].changes[0].attrs | index("enrollment_password") != null)'

cat > "$T/allow.ok" <<'EOF'
# phase       address                                   attrs                          reason
drift-check   keyfactor_certificate_collection.demo     description,enrollment_password   # test: expected write-only + described drift
drift-check   keyfactor_certificate_collection.other    query                          # test
EOF
"$HERE/parse-log.pl" --allowlist "$T/allow.ok" "$FIX/drift.log" > "$T/drift-allowed.json"
jqok "allowlist: fully covered plan -> drift_allowed, not drift" "$T/drift-allowed.json" \
  '(.drift|length) == 0 and (.drift_allowed|length) == 1 and .drift_allowed[0].changes[0].reason != null'

cat > "$T/allow.partial" <<'EOF'
drift-check   keyfactor_certificate_collection.demo   description,enrollment_password   # only one of the two changed resources
EOF
"$HERE/parse-log.pl" --allowlist "$T/allow.partial" "$FIX/drift.log" > "$T/drift-partial.json"
jqok "allowlist: partial coverage still reports the uncovered resource" "$T/drift-partial.json" \
  '(.drift|length) == 1 and ([.drift[0].changes[] | select(.allowlisted == null)] | length) == 1'

cat > "$T/allow.wrongattr" <<'EOF'
drift-check   keyfactor_certificate_collection.*   enrollment_password   # description is NOT covered
EOF
"$HERE/parse-log.pl" --allowlist "$T/allow.wrongattr" "$FIX/drift.log" > "$T/drift-wrongattr.json"
jqok "allowlist: every changed attr must be listed (extra attr -> still drift)" "$T/drift-wrongattr.json" \
  '(.drift|length) == 1'

cat > "$T/allow.bad" <<'EOF'
* * *   # blanket
drift-check keyfactor_certificate_collection.demo description
EOF
"$HERE/parse-log.pl" --allowlist "$T/allow.bad" "$FIX/drift.log" > "$T/drift-bad.json"
jqok "allowlist: blanket rule and rule without reason are rejected, drift stays" "$T/drift-bad.json" \
  '(.allowlist.rejected|length) == 2 and .allowlist.rules == 0 and (.drift|length) == 1'

cat > "$T/compact.log" <<'EOF'
unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN; umask 077; TF_CLI_CONFIG_FILE=x terraform plan
Warnings:

- Provider development overrides are in effect

To see the full warning notes, run Terraform without -compact-warnings.

No changes. Your infrastructure matches the configuration.
EOF
"$HERE/parse-log.pl" "$T/compact.log" > "$T/compact.json"
jqok "compact-warnings bullet list counted; plan line with umask prefix parsed as a clean plan" "$T/compact.json" \
  '.warnings["Provider development overrides are in effect"] == 1 and .plans.clean == 1'

echo "== redaction"
"$HERE/parse-log.pl" "$FIX/secrets.log" > "$T/secrets.json"
printf 'FAKE-LITERAL-9f8e7d6c-XYZ\n' > "$T/values"
HARNESS_REDACT_VALUES_FILE=$T/values "$HERE/parse-log.pl" "$FIX/secrets.log" > "$T/secrets-vals.json"
FAKES='FAKE-SECRET-aaaa1111bbbb FAKE-BEARER-cccc2222dddd3333 eyJFAKEHEADER1 hvs.FAKEVAULTTOKEN0000 FAKE-PASS-eeee4444 FAKE-ENVSECRET-ffff5555 FAKE-OLD-1111aaaa FAKE-NEW-2222bbbb MIIFAKEFAKE'
for s in $FAKES; do nogrep "parser JSON does not contain $s" "$s" "$T/secrets.json"; done
nogrep "parser JSON (values file) does not contain the key-less literal" "FAKE-LITERAL" "$T/secrets-vals.json"
if grep -q "FAKE-LITERAL" "$T/secrets.json"; then ok "key-less literal is only caught via the values file (documented limit)"; else bad "expected the key-less literal to survive without a values file"; fi
HARNESS_REDACT_VALUES_FILE=$T/values "$HERE/redact.pl" < "$FIX/secrets.log" > "$T/secrets.redacted"
for s in $FAKES FAKE-LITERAL FAKE-EXPORTED-TOKEN-0000; do nogrep "redact.pl removes $s" "$s" "$T/secrets.redacted"; done
check "redact.pl keeps token_url" grep -q 'token_url=https://auth.example/token' "$T/secrets.redacted"
check "redact.pl keeps '(sensitive value)'" grep -q 'enrollment_password = (sensitive value)' "$T/secrets.redacted"
check "redact.pl collapses the PEM block" grep -q 'REDACTED PRIVATE KEY BLOCK' "$T/secrets.redacted"
check "redact.pl leaves ordinary lines alone" grep -q 'make\[3\]: \*\*\* \[apply\] Error 1' "$T/secrets.redacted"

echo "== run.sh end to end (fake make)"
export HARNESS_LOG_DIR=$T/logs HARNESS_RESULTS_JSONL=$T/results.jsonl
printf 'KEYFACTOR_AUTH_CLIENT_SECRET=FAKE-LITERAL-9f8e7d6c-XYZ\n' > "$T/envfile"
chmod 600 "$T/envfile"
run() { # run <fixture> <rc> <demo> [extra env...]
  local fx=$1 rc=$2 demo=$3
  shift 3
  env FAKE_FIXTURE="$FIX/$fx" FAKE_RC="$rc" HARNESS_MAKE="$T/fakemake" HARNESS_MODE=dev KEYFACTOR_ENV_FILE="$T/envfile" "$@" "$HERE/run.sh" "$demo"
}
run green.log 0 green_demo > "$T/out.green" 2>&1; rc=$?
[ $rc -eq 0 ] && ok "green: run.sh exits 0" || bad "green: run.sh exit $rc"
lines=$(wc -l < "$T/out.green")
[ "$lines" -le 12 ] && ok "green: stdout is $lines lines (<= 12)" || bad "green: stdout $lines lines"
check "green: first line is HARNESS <demo> PASS" grep -q '^HARNESS green_demo PASS ' "$T/out.green"
run red.log 2 red_demo > "$T/out.red" 2>&1; rc=$?
[ $rc -eq 2 ] && ok "red: run.sh returns the lifecycle exit code (2)" || bad "red: exit $rc, want 2"
lines=$(wc -l < "$T/out.red")
[ "$lines" -le 50 ] && ok "red: stdout is $lines lines (<= 50)" || bad "red: stdout $lines lines"
check "red: stdout names the failing step, error and log range" bash -c "grep -q 'failed: step apply' '$T/out.red' && grep -q 'Unable to create Keyfactor Command certificate' '$T/out.red' && grep -q '^next: sed -n' '$T/out.red'"
run drift.log 0 drift_demo > "$T/out.drift" 2>&1; rc=$?
[ $rc -eq 0 ] && ok "drift: DRIFT does not fail the run by default (exit 0)" || bad "drift: exit $rc"
check "drift: stdout says DRIFT and lists the unexpected resources" bash -c "grep -q '^HARNESS drift_demo DRIFT ' '$T/out.drift' && grep -q 'unexpected' '$T/out.drift'"
run drift.log 0 drift_demo DRIFT_FAIL=1 > "$T/out.drift2" 2>&1; rc=$?
[ $rc -eq 3 ] && ok "drift: DRIFT_FAIL=1 exits 3" || bad "drift: DRIFT_FAIL=1 exit $rc, want 3"
run secrets.log 2 secrets_demo > "$T/out.secrets" 2>&1
for s in $FAKES FAKE-LITERAL; do nogrep "run.sh stdout does not contain $s" "$s" "$T/out.secrets"; done
SJ=$(ls "$T"/logs/secrets_demo-*.summary.json | head -1)
for s in $FAKES FAKE-LITERAL; do nogrep "summary JSON does not contain $s" "$s" "$SJ"; done
L=$(ls "$T"/logs/secrets_demo-*.log | head -1)
check "raw log keeps the original text (owner-only file)" grep -q 'FAKE-SECRET-aaaa1111bbbb' "$L"
[ "$(stat -f %Lp "$L" 2>/dev/null || stat -c %a "$L")" = "600" ] && ok "log file mode is 600" || bad "log file mode is not 600"
[ "$(stat -f %Lp "$SJ" 2>/dev/null || stat -c %a "$SJ")" = "600" ] && ok "summary file mode is 600" || bad "summary file mode is not 600"
n=$(wc -l < "$T/results.jsonl")
[ "$n" -eq 5 ] && ok "harness-results.jsonl got one line per run ($n)" || bad "jsonl lines: $n, want 5"
jqok "jsonl lines are valid single-line JSON with status" "$T/results.jsonl" '.status != null and .demo != null'

echo "== run.sh interrupt"
HARNESS_RESULTS_TXT=$T/results.txt FAKE_SLEEP=6 FAKE_FIXTURE="$FIX/green.log" HARNESS_MAKE="$T/fakemake" HARNESS_MODE=dev KEYFACTOR_ENV_FILE="$T/envfile" "$HERE/run.sh" intr_demo > "$T/out.intr" 2>&1 &
rpid=$!
sleep 1.5
kill -TERM $rpid
wait $rpid; rc=$?
[ $rc -eq 143 ] && ok "interrupt: exit 143" || bad "interrupt: exit $rc"
check "interrupt: INTERRUPTED result line recorded in results.txt" grep -q '^intr_demo,INTERRUPTED' "$T/results.txt"
check "interrupt: output captured before the kill is in the log" grep -q '^starting' "$(ls "$T"/logs/intr_demo-*.log | head -1)"
jqok "interrupt: summary status INTERRUPTED" "$(ls "$T"/logs/intr_demo-*.summary.json | head -1)" '.status == "INTERRUPTED" and .interrupted == true'

echo "== lock"
export KF_HARNESS_LOCK_DIR=$T/locks
"$HERE/with-lock.sh" lockdemo sleep 3 &
lpid=$!
sleep 0.7
"$HERE/with-lock.sh" lockdemo true > /dev/null 2> "$T/lock.err"; rc=$?
[ $rc -eq 75 ] && ok "lock: second run of the same demo is refused (75)" || bad "lock: exit $rc, want 75"
check "lock: refusal names the owner worktree" grep -q 'worktree=' "$T/lock.err"
"$HERE/with-lock.sh" otherdemo true && ok "lock: a different demo is not blocked" || bad "lock: other demo blocked"
wait $lpid
"$HERE/with-lock.sh" lockdemo true && ok "lock: released after the first run ends" || bad "lock: not released"
mkdir -p "$T/locks/stale.lock"
printf 'pid=999999\nworktree=/gone\n' > "$T/locks/stale.lock/owner"
"$HERE/with-lock.sh" stale true > /dev/null && ok "lock: stale lock (dead pid) is reclaimed" || bad "lock: stale lock not reclaimed"
unset KF_HARNESS_LOCK_DIR

echo "== gen-terraformrc.sh"
"$HERE/gen-terraformrc.sh" "$T/bin" "$T/rc.dev"
check "terraformrc: dev_overrides points at the given dir" grep -q "\"keyfactor-pub/keyfactor\" = \"$T/bin\"" "$T/rc.dev"
check "terraformrc: provider dir created" test -d "$T/bin"
m1=$(stat -f %m "$T/rc.dev" 2>/dev/null || stat -c %Y "$T/rc.dev")
sleep 1.1
"$HERE/gen-terraformrc.sh" "$T/bin" "$T/rc.dev"
m2=$(stat -f %m "$T/rc.dev" 2>/dev/null || stat -c %Y "$T/rc.dev")
[ "$m1" = "$m2" ] && ok "terraformrc: idempotent (not rewritten when unchanged)" || bad "terraformrc: rewritten"
[ "$(stat -f %Lp "$T/rc.dev" 2>/dev/null || stat -c %a "$T/rc.dev")" = "600" ] && ok "terraformrc: mode 600" || bad "terraformrc: mode"

echo "== cleanup.sh"
echo 3 > "$T/state"
out=$(STATEFILE=$T/state "$HERE/cleanup.sh" d1 "$T/fakemake" dev); rc=$?
[ $rc -eq 0 ] && echo "$out" | grep -q 'ran=1 destroy_exit=0 state_after=0' && ok "cleanup: state with 3 resources -> destroyed, state_after=0" || bad "cleanup: $out"
out=$(STATEFILE=$T/state "$HERE/cleanup.sh" d1 "$T/fakemake" dev)
echo "$out" | grep -q 'state_before=0 ran=0' && ok "cleanup: empty state -> nothing run" || bad "cleanup: $out"
echo 3 > "$T/state"
out=$(STATEFILE=$T/state FAKE_DESTROY_RC=1 "$HERE/cleanup.sh" d1 "$T/fakemake" dev); rc=$?
[ $rc -eq 1 ] && echo "$out" | grep -q 'destroy_exit=1 state_after=3' && ok "cleanup: failed destroy -> exit 1, resources reported as remaining" || bad "cleanup: rc=$rc $out"
out=$(STATEFILE=$T/state HARNESS_NO_CLEANUP_REASON="shared lab object" "$HERE/cleanup.sh" d1 "$T/fakemake" dev); rc=$?
[ $rc -eq 0 ] && echo "$out" | grep -q 'ran=0.*skipped="shared lab object"' && ok "cleanup: shared-object demo is never destroyed" || bad "cleanup: $out"
out=$(STATEFILE=$T/state FAKE_NO_LABDESTROY=2 "$HERE/cleanup.sh" d1 "$T/fakemake" dev)
echo "$out" | grep -q "running 'destroy'" && ok "cleanup: falls back to 'destroy' when the demo has no lab-destroy" || bad "cleanup: $out"
{ cat "$FIX/red.log"; echo 3 > "$T/state"; STATEFILE=$T/state "$HERE/cleanup.sh" d1 "$T/fakemake" dev; } > "$T/red+cleanup.log"
"$HERE/parse-log.pl" "$T/red+cleanup.log" > "$T/rc.json"
jqok "parser: cleanup result parsed; failing step unchanged by the cleanup destroy" "$T/rc.json" \
  '.cleanup.ran == "1" and .cleanup.state_after == "0" and .failed.step == "apply" and ([.steps[]|select(.cleanup == true)]|length) == 1 and ([.errors[]|select(.cleanup == true)]|length) == 0'

echo "== make harness (streaming, results file, fake make)"
rm -f "$T/results.txt"
out=$(env FAKE_FIXTURE="$FIX/green.log" FAKE_RC=0 HARNESS_MAKE="$T/fakemake" make -C "$TFDIR" harness DEMOS="stream_demo" PROVIDER_MODE=dev RESULTS_FILE="$T/harness-results.txt" HARNESS_MAKE="$T/fakemake" KEYFACTOR_ENV_FILE="$T/envfile" FAKE_FIXTURE="$FIX/green.log" 2>&1); rc=$?
[ $rc -eq 0 ] && ok "harness: exit 0 when every demo passes" || bad "harness: exit $rc"
echo "$out" | grep -q 'Apply complete' && ok "harness: demo output is streamed to stdout" || bad "harness: output not streamed"
grep -q '^stream_demo,PASS,' "$T/harness-results.txt" && ok "harness: harness-results.txt keeps the demo,status,detail format" || bad "harness: results.txt: $(cat "$T/harness-results.txt")"
out=$(make -C "$TFDIR" harness DEMOS="stream_demo" PROVIDER_MODE=dev RESULTS_FILE="$T/harness-results.txt" HARNESS_MAKE="$T/fakemake" KEYFACTOR_ENV_FILE="$T/envfile" FAKE_FIXTURE="$FIX/red.log" FAKE_RC=2 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "^stream_demo,FAIL,exit 2" "$T/harness-results.txt" && ok "harness: a FAIL is recorded as 'exit 2' and fails the harness" || bad "harness: rc=$rc"
make -C "$TFDIR" harness DEMOS="stream_demo" PROVIDER_MODE=dev RESULTS_FILE="$T/harness-results.txt" HARNESS_MAKE="$T/fakemake" KEYFACTOR_ENV_FILE="$T/envfile" FAKE_FIXTURE="$FIX/drift.log" FAKE_RC=0 > "$T/h.drift" 2>&1; rc=$?
[ $rc -eq 0 ] && grep -q '^stream_demo,DRIFT,' "$T/harness-results.txt" && grep -q 'NOTE: DRIFT' "$T/h.drift" && ok "harness: DRIFT shown in the table, does not fail by default" || bad "harness drift: rc=$rc"
make -C "$TFDIR" harness DEMOS="stream_demo" PROVIDER_MODE=dev DRIFT_FAIL=1 RESULTS_FILE="$T/harness-results.txt" HARNESS_MAKE="$T/fakemake" KEYFACTOR_ENV_FILE="$T/envfile" FAKE_FIXTURE="$FIX/drift.log" FAKE_RC=0 > /dev/null 2>&1; rc=$?
[ $rc -ne 0 ] && ok "harness: DRIFT_FAIL=1 makes DRIFT fail the harness" || bad "harness DRIFT_FAIL=1: rc=$rc"

echo "== makefile invariants"
DEMOMK=$TFDIR/certificate_collection_demo
mkdump=$(make -C "$DEMOMK" -pn PROVIDER_MODE=dev 2>/dev/null)
echo "$mkdump" | grep -q '^UNSET_BASIC.*umask 077' && ok "demo-common.mk: UNSET_BASIC sets umask 077" || bad "demo-common.mk: umask missing from UNSET_BASIC"
echo "$mkdump" | grep -q '^LAB_ENV.*umask 077' && ok "demo-common.mk: LAB_ENV sets umask 077" || bad "demo-common.mk: umask missing from LAB_ENV"
echo "$mkdump" | grep -E '^(TF|PROVIDER_BIN) ' | grep -q 'go/bin' && bad "dev mode still references go/bin" || ok "dev mode does not reference ~/go/bin"
echo "$mkdump" | grep '^TF ' | grep -q "TF_CLI_CONFIG_FILE=$TFDIR/.terraformrc.dev" && ok "dev mode TF uses the generated per-worktree .terraformrc.dev" || bad "dev TF is not the generated rc"
echo "$mkdump" | grep '^PROVIDER_BIN' | grep -q "$TFDIR/.provider-bin" && ok "PROVIDER_BIN is this worktree's terraform/.provider-bin" || bad "PROVIDER_BIN not per-worktree"
reg=$(make -C "$DEMOMK" -pn PROVIDER_MODE=registry 2>/dev/null | grep '^TF ')
echo "$reg" | grep -q 'terraformrc.registry' && ok "registry mode still uses .terraformrc.registry" || bad "registry mode changed: $reg"
make -C "$TFDIR" -n certificate_collection_demo-run 2>/dev/null | grep -q 'harness/run.sh certificate_collection_demo' && ok "make -n <demo>-run is a dry print" || bad "<demo>-run recipe"

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
