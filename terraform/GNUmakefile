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
##   PROVIDER_MODE=dev -- TF_CLI_CONFIG_FILE=.terraformrc with dev_overrides
##     pointing at $(HOME)/go/bin (a locally-built provider binary). This is
##     what `harness-dev` uses; each demo's `make build` must run first.
##
## Usage:
##   make harness              # PROVIDER_MODE=registry, all demos
##   make harness-registry     # explicit alias for the above
##   make harness-dev          # PROVIDER_MODE=dev, all demos (builds provider first)
##   make application_demo-lifecycle
##   make store_container_demo-repro175   # demo-specific extra target, if defined

SHELL := /bin/bash
PROVIDER_MODE ?= registry
RESULTS_FILE  := $(CURDIR)/harness-results.txt

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
	certificate_pfx_demo \
	certificate_csr_demo \
	k8s_orchestrator_demo \
	release_validation_demo

# ---------------------------------------------------------------------------
# Per-demo lifecycle targets: `make <demo>-lifecycle` builds the provider (in
# dev mode) and runs that demo's own `make lifecycle`.
# ---------------------------------------------------------------------------
define DEMO_TARGET
.PHONY: $(1)-lifecycle
$(1)-lifecycle:
	@echo "=============================================================="
	@echo "==> $(1) (PROVIDER_MODE=$(PROVIDER_MODE))"
	@echo "=============================================================="
	@if [ "$(PROVIDER_MODE)" = "dev" ]; then $(MAKE) -C $(1) build; fi
	$(MAKE) -C $(1) init PROVIDER_MODE=$(PROVIDER_MODE)
	$(MAKE) -C $(1) lifecycle PROVIDER_MODE=$(PROVIDER_MODE)
endef
$(foreach demo,$(DEMOS),$(eval $(call DEMO_TARGET,$(demo))))

# ---------------------------------------------------------------------------
# Aggregate harness: run every demo's lifecycle, continue past failures,
# record PASS/FAIL/SKIP per demo, print + write a summary table.
#
# A demo counts as SKIP when its own lifecycle target printed a line
# starting with "SKIPPED:" (the convention used by security_identity_demo,
# ca_dcom_demo, ca_ejbca_demo, pam_provider_demo, certificate_authority_demo,
# and certificate_template_demo for lab/credential preconditions that
# aren't met) AND exited 0. A nonzero exit with no SKIPPED marker is a FAIL.
# ---------------------------------------------------------------------------
harness:
	@echo "demo,status,detail" > $(RESULTS_FILE)
	@overall_fail=0; \
	for demo in $(DEMOS); do \
	  echo "=============================================================="; \
	  echo "==> $$demo (PROVIDER_MODE=$(PROVIDER_MODE))"; \
	  echo "=============================================================="; \
	  logfile=$$(mktemp); \
	  $(MAKE) $$demo-lifecycle PROVIDER_MODE=$(PROVIDER_MODE) > "$$logfile" 2>&1; \
	  exit_code=$$?; \
	  cat "$$logfile"; \
	  if [ $$exit_code -eq 0 ] && grep -q "^SKIPPED:" "$$logfile"; then \
	    detail=$$(grep "^SKIPPED:" "$$logfile" | head -1 | sed 's/,/;/g'); \
	    echo "$$demo,SKIP,$$detail" >> $(RESULTS_FILE); \
	    echo ">>> $$demo: SKIP"; \
	  elif [ $$exit_code -eq 0 ]; then \
	    echo "$$demo,PASS," >> $(RESULTS_FILE); \
	    echo ">>> $$demo: PASS"; \
	  else \
	    detail="exit $$exit_code"; \
	    echo "$$demo,FAIL,$$detail" >> $(RESULTS_FILE); \
	    echo ">>> $$demo: FAIL ($$detail)"; \
	    overall_fail=1; \
	  fi; \
	  rm -f "$$logfile"; \
	done; \
	echo; \
	echo "=============================================================="; \
	echo "Harness summary (also written to $(RESULTS_FILE)):"; \
	echo "=============================================================="; \
	column -s, -t $(RESULTS_FILE); \
	exit $$overall_fail

## harness-registry: Explicit alias for `harness` with PROVIDER_MODE=registry
harness-registry:
	$(MAKE) harness PROVIDER_MODE=registry

## harness-dev: Run the harness against a locally-built dev provider binary
harness-dev:
	$(MAKE) harness PROVIDER_MODE=dev

.PHONY: harness harness-registry harness-dev
