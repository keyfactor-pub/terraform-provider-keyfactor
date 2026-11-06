## terraform/GNUmakefile
##
## Top-level orchestrator for the release-test harness: one `<demo>-lifecycle`
## target per demo directory, plus an aggregate `harness` target that runs
## every runnable demo's lifecycle sequentially, continues past individual
## failures, and prints + writes a summary table to harness-results.txt
## (gitignored).
##
## PROVIDER_MODE controls which provider build each demo's `terraform init`
## resolves against:
##   PROVIDER_MODE=registry (default) -- plain `terraform`, real init from
##     the public registry (keyfactor-pub/keyfactor). This is what
##     `harness`/`harness-registry` use.
##   PROVIDER_MODE=dev -- TF_CLI_CONFIG_FILE=terraform/.terraformrc.dev
##     (GENERATED) with dev_overrides pointing at THIS worktree's
##     terraform/.provider-bin (never the shared ~/go/bin, so a run cannot
##     silently test another worktree's build). This is what `harness-dev`
##     uses; each demo's `make build` runs first.
##
## Usage:
##   make harness              # PROVIDER_MODE=registry, all demos
##   make harness-registry     # explicit alias for the above
##   make harness-dev          # PROVIDER_MODE=dev, all demos (builds provider first)
##   make application_demo-lifecycle
##   make store_container_demo-repro175   # demo-specific extra target, if defined
##
## Quiet / agent-friendly (harness/README.md has the details):
##   make <demo>-run                # full log -> .harness-logs/, ~8-line summary on stdout
##   make harness-run               # same for every demo, plus a results table
##   make <demo>-cleanup            # destroy what this worktree's state still tracks
##   make harness-test              # offline tests of the parser/redactor/wrapper
##   DRIFT_FAIL=1 make <demo>-run   # status DRIFT (plan changes) exits 3 instead of 0

SHELL := /bin/bash
PROVIDER_MODE ?= registry
RESULTS_FILE  := $(CURDIR)/harness-results.txt
HARNESS_DIR   := $(CURDIR)/harness
# Kept out of recipe text on purpose: a recipe line that literally contains
# $(MAKE) is executed even under `make -n`; going through a variable keeps
# `make -n <demo>-run` / `-cleanup` truly dry.
HARNESS_MAKE  := $(MAKE)
SUFFIX        ?= _TF
# DRIFT_FAIL=1 turns status DRIFT (lifecycle green, but a `terraform plan`
# step showed changes not covered by the demo's drift-allowlist.txt) into a
# non-zero exit (3) for <demo>-run / harness. Default 0: DRIFT is reported
# loudly in the summary and the results table but does not fail the run.
DRIFT_FAIL    ?= 0
# 1 = `make harness` streams every demo's full output (as it always did);
# `make harness-run` sets 0 (log to file, compact summary per demo).
HARNESS_VERBOSE ?= 1

# Demos whose terraform state tracks SHARED lab objects (imported, not
# created) and which therefore must never be auto-destroyed on failure.
# Their own lab-destroy is already a SKIPPED no-op (prevent_destroy). Every
# other demo creates its resources with the demo's SUFFIX in its own local
# state, so destroying that state cleans up only what the demo made.
NO_CLEANUP_REASON_certificate_authority_demo := imports the shared lab CA (prevent_destroy); never destroyed by design
NO_CLEANUP_REASON_certificate_template_demo  := imports shared lab certificate templates; never destroyed by design

# ---------------------------------------------------------------------------
# All demos in the harness, in a stable, deliberate run order: cheap/fast
# read-mostly demos first, certificate-issuing and K8S-heavy demos last.
# ecc_pfx_debug and _state_archive_* are NOT part of the harness.
# ---------------------------------------------------------------------------
## security_identity_demo (keyfactor_identity) is a PERMANENT structural
## no-op against kfclab: the resource only supports Active Directory
## identities, and kfclab is Authentik-OAuth-only with no AD backend (see
## security_identity_demo/README.md for the exact HTTP 400 and the
## SKIP_LAB_AD default that makes its lifecycle print SKIPPED and exit 0).
## A green harness run therefore proves NOTHING about this resource's
## correctness -- `make testunit`'s TestUnitSecurityIdentity* suite in
## keyfactor/resource_keyfactor_security_identity_unit_test.go is the
## REQUIRED, non-optional substitute regression gate and MUST be green
## before any release. In particular:
##   TestUnitSecurityIdentityResource_CreateFailsOnRoleLookupError
##     (Create() silently dropping an unresolvable role instead of failing)
##   TestUnitSecurityIdentityResource_ResolveDeclaredSecurityRoleIdPathResolvesWithWarning
##     (numeric role IDs never resolving via the name-query lookup)
##   TestUnitSecurityIdentityResource_UpdateRejectsUnverifiedRoleNameMatch
##     (unescaped PQL role-name query allowing an unverified match through)
## These are unit tests against a mock server, not live-lab coverage --
## they are the best available regression gate for this specific resource,
## not equivalent to it.
DEMOS := \
	oauth_security_demo \
	pam_provider_type_demo \
	pam_provider_demo \
	security_role_demo \
	security_role_permissions_demo \
	security_identity_demo \
	template_role_binding_demo \
	certificate_authority_demo \
	certificate_template_demo \
	ca_schedule_demo \
	ca_dcom_demo \
	ca_ejbca_demo \
	application_demo \
	store_type_demo \
	store_container_demo \
	certificate_collection_demo \
	enrollment_pattern_demo \
	certificate_pfx_demo \
	certificate_csr_demo \
	k8s_orchestrator_demo \
	release_validation_demo

# ---------------------------------------------------------------------------
# Per-demo targets (generated for every demo in DEMOS):
#   <demo>-lifecycle  build (dev) + init + the demo's own `make lifecycle`, holding a
#                     cross-worktree per-demo lock (harness/with-lock.sh). If the
#                     lifecycle FAILS, <demo>-cleanup runs automatically and the
#                     ORIGINAL exit code is preserved.
#   <demo>-cleanup    destroy whatever this worktree's local state still tracks for
#                     the demo (harness/cleanup.sh). Safe to run by hand.
#   <demo>-run        quiet wrapper: full log -> .harness-logs/, compact summary
#                     on stdout, summary JSON + harness-results.jsonl (harness/run.sh)
# ---------------------------------------------------------------------------
define DEMO_TARGET
.PHONY: $(1)-lifecycle $(1)-lifecycle-body $(1)-cleanup $(1)-run
$(1)-lifecycle:
	@$(HARNESS_DIR)/with-lock.sh $(1) $(MAKE) $(1)-lifecycle-body PROVIDER_MODE=$(PROVIDER_MODE)

$(1)-lifecycle-body:
	@echo "=============================================================="
	@echo "==> $(1) (PROVIDER_MODE=$(PROVIDER_MODE))"
	@echo "=============================================================="
	@if [ "$(PROVIDER_MODE)" = "dev" ]; then $(MAKE) -C $(1) build; fi
	$(MAKE) -C $(1) init PROVIDER_MODE=$(PROVIDER_MODE)
	@$(MAKE) -C $(1) lifecycle PROVIDER_MODE=$(PROVIDER_MODE); rc=$$$$?; \
	 if [ $$$$rc -ne 0 ]; then \
	   echo "==> $(1): lifecycle FAILED (exit $$$$rc); cleaning up whatever this worktree state still tracks"; \
	   $(MAKE) $(1)-cleanup PROVIDER_MODE=$(PROVIDER_MODE); crc=$$$$?; \
	   echo "==> $(1): cleanup exit $$$$crc; propagating the lifecycle exit code $$$$rc"; \
	 fi; \
	 chmod -f 600 $(1)/tf_state.json $(1)/terraform.tfstate* 2>/dev/null; \
	 exit $$$$rc

$(1)-cleanup:
	@HARNESS_NO_CLEANUP_REASON='$(NO_CLEANUP_REASON_$(1))' $(HARNESS_DIR)/cleanup.sh $(1) '$(HARNESS_MAKE)' $(PROVIDER_MODE)

$(1)-run:
	@HARNESS_MODE=$(PROVIDER_MODE) HARNESS_SUFFIX='$(SUFFIX)' HARNESS_MAKE='$(HARNESS_MAKE)' DRIFT_FAIL=$(DRIFT_FAIL) $(HARNESS_DIR)/run.sh $(1)
endef
$(foreach demo,$(DEMOS),$(eval $(call DEMO_TARGET,$(demo))))

# ---------------------------------------------------------------------------
# Aggregate harness: run every demo's lifecycle, continue past failures,
# record PASS/FAIL/SKIP/DRIFT/... per demo, print + write a summary table.
#
# Each demo goes through harness/run.sh, which tees the demo's output into
# .harness-logs/<demo>-<ts>.log AS IT RUNS (so a killed run keeps its output),
# traps INT/TERM and still records a result line (status INTERRUPTED), and
# appends to harness-results.txt (this CSV, same format as before, with the
# new statuses DRIFT / INTERRUPTED / AUTH_PREFLIGHT_FAIL) and to
# harness-results.jsonl (one JSON object per run).
#
# A demo counts as SKIP when its own lifecycle target printed a line
# starting with "SKIPPED:" (the convention used by security_identity_demo,
# ca_dcom_demo, ca_ejbca_demo, pam_provider_demo, certificate_authority_demo,
# and certificate_template_demo for lab/credential preconditions that
# aren't met) AND exited 0. A nonzero exit with no SKIPPED marker is a FAIL.
# DRIFT = lifecycle exited 0 but a `terraform plan` step showed changes that
# the demo's drift-allowlist.txt does not cover; it only fails the harness
# when DRIFT_FAIL=1.
# ---------------------------------------------------------------------------
harness:
	@echo "demo,status,detail" > $(RESULTS_FILE)
	@overall_fail=0; \
	for demo in $(DEMOS); do \
	  if [ "$(HARNESS_VERBOSE)" = "1" ]; then \
	    echo "=============================================================="; \
	    echo "==> $$demo (PROVIDER_MODE=$(PROVIDER_MODE))"; \
	    echo "=============================================================="; \
	  fi; \
	  HARNESS_VERBOSE=$(HARNESS_VERBOSE) HARNESS_RESULTS_TXT=$(RESULTS_FILE) \
	    HARNESS_MODE=$(PROVIDER_MODE) HARNESS_SUFFIX='$(SUFFIX)' HARNESS_MAKE='$(HARNESS_MAKE)' \
	    DRIFT_FAIL=$(DRIFT_FAIL) $(HARNESS_DIR)/run.sh $$demo || overall_fail=1; \
	done; \
	echo; \
	echo "=============================================================="; \
	echo "Harness summary (also written to $(RESULTS_FILE)):"; \
	echo "=============================================================="; \
	column -s, -t $(RESULTS_FILE); \
	if grep -q ',DRIFT,' $(RESULTS_FILE); then \
	  echo "NOTE: DRIFT = lifecycle passed but a plan step showed unexpected changes (DRIFT_FAIL=$(DRIFT_FAIL))."; \
	fi; \
	exit $$overall_fail

## harness-registry: Explicit alias for `harness` with PROVIDER_MODE=registry
harness-registry:
	$(MAKE) harness PROVIDER_MODE=registry

## harness-dev: Run the harness against a locally-built dev provider binary
harness-dev:
	$(MAKE) harness PROVIDER_MODE=dev

## harness-run: Same as `harness` but quiet: per demo only the compact summary
## reaches stdout (full logs in .harness-logs/), then the results table.
harness-run:
	$(MAKE) harness HARNESS_VERBOSE=0

## harness-test: Offline tests (no lab, no network) of the log parser, secret
## redactor, run wrapper, lock and cleanup logic against recorded fixtures.
harness-test:
	@$(HARNESS_DIR)/test.sh

## harness-tighten-perms: chmod 600/700 every state/plan/secret-bearing artifact
## under terraform/ (tfstate*, tf_state.json, *.tfplan, .harness-logs). New runs
## already create them owner-only (umask 077); this fixes leftovers.
harness-tighten-perms:
	@find . \( -name 'terraform.tfstate*' -o -name 'tf_state.json' -o -name '*.tfplan' -o -name 'tfplan*' -o -name '.env' -o -name 'sa-context.json' -o -name '*.pfx' -o -name 'harness-results*' \) -type f -exec chmod 600 {} + ; \
	 if [ -d .harness-logs ]; then chmod 700 .harness-logs; find .harness-logs -type f -exec chmod 600 {} + ; fi; \
	 echo "tightened state/plan/secret artifacts under $(CURDIR)"

.PHONY: harness harness-registry harness-dev harness-run harness-test harness-tighten-perms
