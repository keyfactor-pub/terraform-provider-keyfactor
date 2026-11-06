#!/bin/bash
# cleanup.sh <demo> <make> <provider-mode>
#
# Failure cleanup for `make <demo>-lifecycle` (and `make <demo>-cleanup` by
# hand). Terraform state is LOCAL to each demo directory, so `lab-destroy`
# only ever destroys what THIS worktree's state tracks, i.e. what this demo
# applied (or imported). Steps:
#   1. count resources in the demo's state (make state-count);
#   2. nothing in state  -> nothing to do (demos with their own cleanup, e.g.
#      store_type/template_role_binding/store_container/ca_schedule, are
#      usually already empty here);
#   3. $HARNESS_NO_CLEANUP_REASON set -> the demo imports SHARED lab objects
#      and must never destroy them: report and stop;
#   4. otherwise run the demo's own lab-destroy (or `destroy` if it has no
#      lab-* wrapper) and recount.
# Always prints one machine-readable line:
#   HARNESS-CLEANUP: demo=.. state_before=N ran=0|1 destroy_exit=rc state_after=M [skipped="reason"]
# and exits 0 if state is empty afterwards (or cleanup was intentionally
# skipped), 1 if resources remain after an attempted destroy.
demo=$1
MAKE_BIN=${2:-make}
mode=${3:-registry}
HERE=$(cd "$(dirname "$0")" && pwd)
TFDIR=$(dirname "$HERE")

count() {
  "$MAKE_BIN" --no-print-directory -s -C "$TFDIR/$demo" state-count PROVIDER_MODE="$mode" 2>/dev/null \
    | grep -E '^[0-9]+$' | tail -1
}

echo "HARNESS-CLEANUP-BEGIN demo=$demo"
before=$(count); before=${before:-unknown}
if [ "$before" = "0" ]; then
  echo "HARNESS-CLEANUP: demo=$demo state_before=0 ran=0 destroy_exit=- state_after=0"
  exit 0
fi
if [ -n "${HARNESS_NO_CLEANUP_REASON:-}" ]; then
  echo "HARNESS-CLEANUP: demo=$demo state_before=$before ran=0 destroy_exit=- state_after=$before skipped=\"$HARNESS_NO_CLEANUP_REASON\""
  exit 0
fi
target=lab-destroy
"$MAKE_BIN" --no-print-directory -n -C "$TFDIR/$demo" lab-destroy PROVIDER_MODE="$mode" >/dev/null 2>&1 || target=destroy
echo "==> cleanup: $demo has $before resource(s) in state; running '$target'"
"$MAKE_BIN" --no-print-directory -C "$TFDIR/$demo" "$target" PROVIDER_MODE="$mode"
rc=$?
after=$(count); after=${after:-unknown}
echo "HARNESS-CLEANUP: demo=$demo state_before=$before ran=1 destroy_exit=$rc state_after=$after"
[ "$after" = "0" ] && exit 0
exit 1
