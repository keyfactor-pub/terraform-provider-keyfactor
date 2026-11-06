# format-summary.jq: compact stdout report for one run (see format-summary.sh)
def dur: (.duration_s // 0) as $s | if $s >= 3600 then "\($s/3600|floor)h\(($s%3600)/60|floor)m" elif $s >= 60 then "\($s/60|floor)m\($s%60)s" else "\($s)s" end;
def cnt($p): if $p == null then "" else "+\($p.add)~\($p.change)-\($p.destroy)" end;
def tok:
  (if .cleanup then "cleanup:" else "" end) +
  (if .cmd == "plan" then
      "plan" + (if .phase == "plan" then "" else "(\(.phase))" end) + "=" + (if .result == "clean" then "clean" elif .result == "changes" then "CHANGES" + cnt(.plan) else .result end)
   elif .cmd == "apply" then "apply=" + (if .result == "applied" then cnt(.applied) elif .result == "no-op" then "no-op" else .result end)
   elif .cmd == "destroy" then "destroy=" + (if .result == "destroyed" then "-\(.applied.destroy)" else .result end)
   elif (.cmd | IN("init","build","import")) then .cmd + "=" + .result
   else empty end);
def lines_cap($n): if length > $n then .[:$n] + ["    ... (\(length - $n) more line(s) in the log)"] else . end;

"HARNESS \(.demo) \(.status) \(dur) head=\(.head)\(if .dirty then "+dirty" else "" end) mode=\(.mode) suffix=\(.suffix)",
( [ .steps[] | select(.cmd != "show" and (.cmd | startswith("state") | not) and .cmd != "output" and .cmd != "validate") | tok ] as $t
  | "steps: " + ($t | join(" ")) ),
"plans: \(.plans.total) total, \(.plans.clean) clean, \(.plans.with_changes) with changes"
  + (if (.drift | length) > 0 then " (DRIFT: \(.drift | length) unexpected)" elif (.drift_allowed | length) > 0 then " (\(.drift_allowed | length) allowlisted)" else "" end)
  + " | provider: \(.provider.path // "n/a")\(if .provider.sha256 then " sha256:\(.provider.sha256)" else "" end)",
( if .skipped then "skipped: \(.skipped)" else empty end ),
( if .auth_preflight then "auth preflight failed (\(.auth_preflight)); run `make lab-env-refresh` against a copy of the env file" else empty end ),
( if .status == "INTERRUPTED" then "interrupted: run was killed mid-flight; lab resources may remain, check with `make \(.demo)-cleanup`" else empty end ),
( if .failed then
    "failed: step \(.failed.step // "?") in phase \(.failed.phase // "?") (log lines \(.failed.lines[0])-\(.failed.lines[1]), exit \(.failed.exit)); chain: \([.failed.chain[].target] | join(" <- "))"
  else empty end ),
( if (.errors | length) > 0 then
    ( [ .errors[] | select(.cleanup | not) ] as $e
      | ($e | length) as $n
      | ( $e[:3] | to_entries[]
          | "error \(.key + 1)/\($n): \(.value.summary)" + (if .value.resource then " [\(.value.resource)" + (if .value.at then " @ \(.value.at)" else "" end) + "]" else "" end) + " (log \(.value.log_line)-\(.value.log_end))",
            ( .value.detail | map(select(test("\\S"))) | lines_cap(14) | .[] | "    " + . ) ),
        ( if $n > 3 then "    ... \($n - 3) more error block(s); see summary JSON" else empty end ) )
  else empty end ),
( .harness_fail[:5][] | "  " + . ),
( .plain_errors[:5][] | "  " + . ),
( if (.drift | length) > 0 then
    ( .drift[:6][] as $d
      | "DRIFT in plan step \($d.phase) (log line \($d.line)):",
        ( $d.changes[:6][] | "  \(.address) \(.action)" + (if (.attrs | length) > 0 then " [" + (.attrs | join(",")) + "]" else "" end) + (if .allowlisted then "  (allowlisted: \(.reason))" else "  <-- unexpected" end) ) ),
    ( if (.drift | length) > 6 then "  ... \((.drift | length) - 6) more drifting plan step(s); see summary JSON" else empty end )
  else empty end ),
( if (.allowlist.rejected | length) > 0 then "allowlist: \(.allowlist.rejected | length) rule(s) rejected (\(.allowlist.rejected[0].why))" else empty end ),
( if .cleanup then
    "cleanup: " + (if .cleanup.skipped then "skipped (\(.cleanup.skipped)); \(.cleanup.state_after) resource(s) remain in state"
                   elif .cleanup.ran == "1" then "ran lab-destroy, exit \(.cleanup.destroy_exit); resources in state \(.cleanup.state_before) -> \(.cleanup.state_after)"
                   else "nothing to destroy (state empty)" end)
  else empty end ),
"log: \(.log) (\(.log_lines) lines)",
"summary: \(.summary)",
( if .failed then (if (.errors | map(select(.cleanup | not)) | length) > 0 then (.errors | map(select(.cleanup | not)) | .[0]) as $e | "next: sed -n \"\($e.log_line),\($e.log_end)p\" \(.log)   (whole failing step: lines \(.failed.lines[0])-\(.failed.lines[1]))" else "next: sed -n \"\(.failed.lines[0]),\(.failed.lines[1])p\" \(.log)" end) else empty end )
