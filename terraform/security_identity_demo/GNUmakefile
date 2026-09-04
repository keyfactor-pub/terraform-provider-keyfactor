## security_identity_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of the legacy keyfactor_identity
## resource, and proves PR #179 (make `roles` Optional+Computed to fix
## "Provider produced inconsistent result after apply" when an Update omits
## `roles` from config):
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## The `lab-omit-roles-update` target is the actual regression proof for
## PR #179: it applies the identity WITH roles declared, then applies again
## with `roles` omitted from config entirely -- this must succeed without
## the inconsistent-result crash, and the identity's role assignment must
## remain present server-side afterward.
##
## LAB CONSTRAINT: keyfactor_identity manages Active Directory identities
## only. The default kfclab lab (KEYFACTOR_ENV_FILE) is Authentik-OAuth-backed
## with no AD, so `apply` here fails at Create with HTTP 400 "This operation
## only supports Active Directory identities" for ANY account_name --
## confirmed directly against the Command REST API. This is a structural lab
## gap, not a provider defect. SKIP_LAB_AD defaults to 1: `make lifecycle`
## prints "SKIPPED: ..." and exits 0 without touching the lab. Set
## SKIP_LAB_AD=0 and point account_name at a real AD-backed lab account (not
## yet a Keyfactor security identity) to exercise this demo end-to-end; see
## discoverCreatableIdentity in
## keyfactor/resource_keyfactor_security_identity_test.go for the pattern
## this repo's integration tests use.
##
## Usage:
##   cd terraform/security_identity_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make SKIP_LAB_AD=0 ACCOUNT_NAME='DOMAIN\\user' lifecycle   # run against an AD-backed lab
##   make SUFFIX=_MYORG all  # run with a custom name suffix

ACCOUNT_NAME   ?= KEYFACTOR\\Administrator
SKIP_LAB_AD    ?= 1

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)" -var="account_name=$(ACCOUNT_NAME)"

## apply: Create the security identity resource
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="account_name=$(ACCOUNT_NAME)"

## import-all: Remove the managed resource from state then re-import by its real account name
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	@echo "==> Extracting account name from state..."
	@ACCT=$$($(UNSET_BASIC) $(TF) output -raw identity_account_name 2>/dev/null) && \
	 echo "Account Name=$$ACCT" && \
	 echo "==> Removing from state..." && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_identity.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 echo "==> Re-importing by real account name..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" -var="account_name=$(ACCOUNT_NAME)" keyfactor_identity.demo "$$ACCT"

## reconcile: Apply after import to reconcile fields not returned by the API
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)" -var="account_name=$(ACCOUNT_NAME)"

## drift-check: Plan after reconcile (should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)" -var="account_name=$(ACCOUNT_NAME)"

## destroy: Destroy the managed security identity resource
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)" -var="account_name=$(ACCOUNT_NAME)"

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow: build, init, validate, plan, apply, import-all, reconcile, drift-check, destroy
all: build init validate plan apply import-all reconcile drift-check destroy

## demo-no-destroy: Run workflow without final destroy (leaves resources on server)
demo-no-destroy: build init validate plan apply import-all reconcile drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source KEYFACTOR_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-plan: Plan using lab credentials
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX) ACCOUNT_NAME='$(ACCOUNT_NAME)'

## lab-apply: Apply using lab credentials
lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX) ACCOUNT_NAME='$(ACCOUNT_NAME)'

## lab-import-all: Import all resources using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX) ACCOUNT_NAME='$(ACCOUNT_NAME)'

## lab-reconcile: Reconcile after import
lab-reconcile:
	$(LAB_ENV) $(MAKE) reconcile SUFFIX=$(SUFFIX) ACCOUNT_NAME='$(ACCOUNT_NAME)'

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX) ACCOUNT_NAME='$(ACCOUNT_NAME)'

## lab-destroy: Destroy all managed resources using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX) ACCOUNT_NAME='$(ACCOUNT_NAME)'

## lifecycle: Full lifecycle: apply → import-all → reconcile → drift-check → destroy
##   SKIP_LAB_AD=1 (default): this lab has no AD backing (see header) --
##   prints SKIPPED and exits 0 instead of running (and failing) apply.
##   SKIP_LAB_AD=0: runs the real lifecycle against ACCOUNT_NAME.
lifecycle:
	@if [ "$(SKIP_LAB_AD)" = "1" ]; then \
	  echo "SKIPPED: security_identity_demo requires an AD-backed lab (kfclab is OAuth-only). Set SKIP_LAB_AD=0 and ACCOUNT_NAME to run."; \
	else \
	  $(MAKE) lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy; \
	fi

# ---------------------------------------------------------------------------
# PR #179 regression proof: roles omitted on an Update
#
#   1. apply with roles declared (roles_declared=true)
#   2. apply again with roles omitted from config (roles_declared=false) --
#      pre-fix this crashed terraform apply with "Provider produced
#      inconsistent result after apply: .roles: was null, but now
#      cty.ListVal(...)"; post-fix this must succeed cleanly
#   3. verify via a direct Command REST API call that the identity's roles
#      are still intact server-side (preserved, not cleared)
#   4. destroy
#
# NOTE: unlike keyfactor_role's lab-omit-permissions-update, this scenario
# needs no unrelated-attribute change to force an Update call: the plan
# diff on `roles` alone (list -> null, pre-fix) is what makes Terraform Core
# call Update in the first place. keyfactor_identity has no other
# user-settable attribute besides account_name (RequiresReplace).
# ---------------------------------------------------------------------------

## lab-omit-roles-update: Regression proof for PR179 (roles Optional+Computed fix)
lab-omit-roles-update:
	@echo "==> [1/4] apply WITH roles declared..."
	$(LAB_ENV) $(TF) apply -auto-approve \
	  -var="suffix=$(SUFFIX)" \
	  -var="account_name=$(ACCOUNT_NAME)" \
	  -var="roles_declared=true"
	@echo "==> [2/4] apply again with roles OMITTED from config..."
	@APPLYFILE=$$(mktemp) && \
	 echo "    scratch apply-log file: $$APPLYFILE" && \
	 $(LAB_ENV) $(TF) apply -auto-approve -no-color \
	  -var="suffix=$(SUFFIX)" \
	  -var="account_name=$(ACCOUNT_NAME)" \
	  -var="roles_declared=false" > "$$APPLYFILE" 2>&1; \
	 APPLY_EXIT=$$?; \
	 cat "$$APPLYFILE"; \
	 rm -f "$$APPLYFILE"; \
	 if [ $$APPLY_EXIT -eq 0 ]; then \
	   echo "PASS: apply succeeded with roles omitted on Update (PR179 fix confirmed)."; \
	 else \
	   echo "FAIL: apply failed (exit $$APPLY_EXIT) -- inconsistent-result-after-apply regression."; \
	   exit 1; \
	 fi
	@echo "==> [3/4] verify roles are still intact server-side (direct Command API call)..."
	@$(LAB_ENV) \
	 ACCT=$$($(TF) output -raw identity_account_name) && \
	 echo "    target identity: $$ACCT" && \
	 $(KF_CURL_AUTH) \
	 RESPFILE=$$(mktemp) && \
	 echo "    scratch response file: $$RESPFILE" && \
	 curl -s $$CURL_TLS "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Security/Identities" \
	   -H "x-keyfactor-requested-with: APIClient" \
	   -H "x-keyfactor-api-version: 1" \
	   -K "$$KFCFG" > "$$RESPFILE" && \
	 rm -f "$$KFCFG" && \
	 jq --arg acct "$$ACCT" '.[] | select(.AccountName == $$acct)' "$$RESPFILE" && \
	 if jq -e --arg acct "$$ACCT" '.[] | select(.AccountName == $$acct) | .Roles | length > 0' "$$RESPFILE" > /dev/null; then \
	   rm -f "$$RESPFILE"; \
	   echo "PASS: server-side roles are still present -- preserved, not cleared."; \
	 else \
	   rm -f "$$RESPFILE"; \
	   echo "FAIL: server-side roles are empty -- roles were cleared."; \
	   exit 1; \
	 fi
	@echo "==> [4/4] destroy..."
	$(LAB_ENV) $(TF) destroy -auto-approve \
	  -var="suffix=$(SUFFIX)" \
	  -var="account_name=$(ACCOUNT_NAME)" \
	  -var="roles_declared=false"

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle lab-omit-roles-update
