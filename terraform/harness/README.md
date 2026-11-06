# terraform/harness: quiet runner, drift report, isolation

Helpers behind `make <demo>-run`, `make harness`, `make harness-run` in
`terraform/GNUmakefile`. Nothing here changes what a demo's own `lifecycle`
does; it wraps it.

## Commands (run from `terraform/`)

```bash
make PROVIDER_MODE=dev KEYFACTOR_ENV_FILE=~/.env_x certificate_collection_demo-run
make PROVIDER_MODE=dev harness-run          # every demo, one compact block each + results table
make harness                                 # legacy verbose harness (streams full output, still logs)
make <demo>-lifecycle                        # unchanged entry point (now: lock + auto-cleanup on failure)
make <demo>-cleanup                          # destroy what this worktree's state still tracks
make harness-test                            # offline tests (no lab, no terraform)
make harness-tighten-perms                   # chmod 600 leftover state/plan/secret files
DRIFT_FAIL=1 make <demo>-run                 # status DRIFT exits 3 (default: reported, exit 0)
```

`<demo>-run` exit code = the lifecycle's exit code (130/143 if interrupted, 3 for
DRIFT with `DRIFT_FAIL=1`).

## What `-run` writes

| File | Content |
|---|---|
| `.harness-logs/<demo>-<UTC>.log` | full output (raw: may contain secrets; dir 700, file 600, gitignored) |
| `.harness-logs/<demo>-<UTC>.summary.json` | `kf-harness-summary/v1`, secret-redacted excerpts |
| `harness-results.jsonl` | one compact JSON line per run (gitignored) |
| `harness-results.txt` | `demo,status,detail` CSV, only written by `harness`/`harness-run` (as before) |

Status: `PASS | FAIL | SKIP | DRIFT | INTERRUPTED | AUTH_PREFLIGHT_FAIL`.

stdout is about 8 lines on green and at most about 50 on red: header, step list with plan counts,
failing step/phase/exit and the `make` error chain, the error blocks (secret-redacted, 14 lines each,
3 blocks max), cleanup outcome, log path, and `next: sed -n "A,Bp" <log>` for the failing block.

Quiet flags exported to terraform (verified with `terraform <cmd> -help` on 1.17.1; injected via
`TF_CLI_ARGS_<cmd>`, so no makefile edits): `TF_IN_AUTOMATION=1`; `-no-color -input=false` on
init/import/plan/apply/destroy; `-compact-warnings` on plan/apply/destroy; `-no-color` on
validate/show/output. `terraform state rm` accepts none of them.

## Drift

`drift-check` (and the plan after each update) is a plain `terraform plan`, so the lifecycle exits 0
even when the plan shows changes. The parser reads every `terraform plan` step in the log (`Plan: N to
add...` / `No changes.` and the `# addr will be updated in-place` blocks) and reports DRIFT when any
shows changes that are not allowlisted. Plan text, not `-detailed-exitcode`, because make collapses
every failure to exit 2 and 19 recipes would have to change; both agree (`-detailed-exitcode` gives 0/2).

Per-demo allowlist: `terraform/<demo>/drift-allowlist.txt`, one rule per line:

```
# <phase-glob>  <address-glob>               <attr>[,attr...]   # reason (required)
drift-check     keyfactor_pam_provider.demo  param_values       # secret param_value is write-only
```

Rules: only in-place updates can be allowlisted; every changed attribute of a resource must be listed;
a missing reason or a blanket `* * *` rule is rejected (and shown in the summary). Allowlisted drift is
still listed in the summary (`drift_allowed`).

## Isolation

* Dev mode builds into `terraform/.provider-bin` (this worktree only, never `~/go/bin`), and
  `terraform/.terraformrc.dev` is generated from that path at make-parse time. The run prints
  `==> Provider binary: <path> (sha256 ...)` and records it in the summary.
* `<demo>-lifecycle` takes a per-demo lock shared by all worktrees of the user
  (`~/.cache/kf-terraform-harness/locks`, override `KF_HARNESS_LOCK_DIR`; bypass `HARNESS_NO_LOCK=1`).
  A second run of the same demo from another worktree is refused with exit 75, because they would fight
  over the same lab objects.
* `SUFFIX` defaults to `_TF` everywhere, and some demos use FIXED lab names (k8s_orchestrator_demo:
  client_machine `k8s-orchestrator-tf-demo`, stores/secrets `tf-demo-*`; certificate_authority_demo and
  certificate_template_demo import shared lab objects by design). The lock prevents concurrent
  collisions; it cannot prevent a sequential run from another worktree finding leftovers. For
  concurrent work from two worktrees on suffix-aware demos, give each its own suffix:
  `make SUFFIX=_wt2 <demo>-run`. Making k8s_orchestrator_demo suffix-aware needs a `name_suffix`
  variable (default empty, so existing lab names stay) threaded through stores.tf/deployments.tf and its
  GNUmakefile; not done here.

## Failure cleanup

If a demo's lifecycle exits non-zero, `<demo>-lifecycle` runs `<demo>-cleanup` (harness/cleanup.sh)
and still exits with the lifecycle's original code. Terraform state is local to each demo directory, so
`lab-destroy` only touches what this worktree's state tracks (what this demo applied). It is skipped
when state is empty (demos with their own cleanup are usually already empty) and never runs for
certificate_authority_demo / certificate_template_demo (shared objects, `NO_CLEANUP_REASON_*` in
GNUmakefile). The outcome is printed as `HARNESS-CLEANUP: ... state_before=N ran=0|1 destroy_exit=rc
state_after=M` and shown in the summary. An interrupted run is NOT cleaned automatically; run
`make <demo>-cleanup`.

## Files / permissions

`umask 077` is set in `UNSET_BASIC` and `LAB_ENV` (demo-common.mk), so `terraform.tfstate*`,
`tf_state.json` (plaintext sensitive values) and plan files are created owner-only. Terraform keeps the
mode of an existing state file, so `run.sh` also chmods leftovers after each run.

## Offline tests

`make harness-test` (about 100 checks). Fixtures: `fixtures/green.log`, `fixtures/red.log` are real
recorded runs (sanitized); `fixtures/drift.log` and `fixtures/secrets.log` are synthetic and say so on
line 1. The parser is `parse-log.pl` (perl, core modules only, because it is a line state machine);
everything else is bash + jq.
