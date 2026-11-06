#!/bin/bash
# with-lock.sh <demo> <command...>
#
# Runs <command> while holding a per-demo lock shared by ALL worktrees of this
# user on this machine (default dir: ~/.cache/kf-terraform-harness/locks;
# override with KF_HARNESS_LOCK_DIR). Two worktrees running the same demo at
# once would fight over the same lab objects (default SUFFIX is _TF everywhere
# and e.g. k8s_orchestrator_demo uses FIXED store names), so the second one is
# refused loudly (exit 75) instead of colliding silently.
#
# The lock is an atomic mkdir; a lock whose owning pid is dead is reclaimed.
# HARNESS_NO_LOCK=1 bypasses (use only when you know the other run is gone).
# Dry runs (make -n) skip the lock.
demo=$1
shift
first=${MAKEFLAGS:-}
first=${first%% *}
case $first in
  -*) ;;
  *n*) exec "$@" ;;
esac
case " ${MAKEFLAGS:-} " in
  *" -n "*|*" --just-print "*|*" --dry-run "*) exec "$@" ;;
esac
if [ "${HARNESS_NO_LOCK:-0}" = "1" ]; then exec "$@"; fi

root=${KF_HARNESS_LOCK_DIR:-$HOME/.cache/kf-terraform-harness/locks}
mkdir -p "$root"
lock=$root/$demo.lock
worktree=$(cd "$(dirname "$0")/../.." && pwd)

acquire() { mkdir "$lock" 2>/dev/null; }
if ! acquire; then
  owner_pid=$(sed -n 's/^pid=//p' "$lock/owner" 2>/dev/null)
  if [ -n "$owner_pid" ] && ! kill -0 "$owner_pid" 2>/dev/null; then
    echo "HARNESS-LOCK: reclaiming stale lock for $demo (pid $owner_pid is gone)"
    rm -rf "$lock"
    acquire || { echo "HARNESS-LOCK: lost the race reclaiming $demo lock" >&2; exit 75; }
  else
    echo "HARNESS-LOCK: $demo is already running from another worktree/session and would collide on the same lab objects:" >&2
    sed 's/^/  /' "$lock/owner" >&2 2>/dev/null
    echo "  (lock: $lock; set HARNESS_NO_LOCK=1 to bypass if you are sure it is stale)" >&2
    exit 75
  fi
fi
printf 'pid=%s\nworktree=%s\nstarted=%s\n' "$$" "$worktree" "$(date -u +%FT%TZ)" > "$lock/owner"
release() { rm -rf "$lock"; }
trap release EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
"$@"
