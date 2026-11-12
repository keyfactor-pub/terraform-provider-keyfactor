## oauth_security_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of OAuth security resources:
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/oauth_security_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make all                # run the full workflow
##   make SUFFIX=_MYORG all  # run with a custom name suffix

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create all OAuth security resources
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove all managed resources from state then re-import by their real IDs
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	@echo "==> Extracting IDs from state..."
	@# Role: import by name
	@ROLE_NAME=$$($(UNSET_BASIC) $(TF) output -raw role_name 2>/dev/null) && \
	 CLAIM_ID=$$($(UNSET_BASIC) $(TF) output -raw claim_id 2>/dev/null) && \
	 ROLE_ID=$$($(UNSET_BASIC) $(TF) output -raw role_id 2>/dev/null) && \
	 echo "Role Name=$$ROLE_NAME  Claim ID=$$CLAIM_ID  Role ID=$$ROLE_ID" && \
	 echo "==> Removing from state..." && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_oauth_security_role_claim_association.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_oauth_security_claim.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_oauth_security_role.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 echo "==> Re-importing by real IDs..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_oauth_security_role.demo "$$ROLE_NAME" && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_oauth_security_claim.demo "$$CLAIM_ID" && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_oauth_security_role_claim_association.demo "$$ROLE_ID/$$CLAIM_ID"

## reconcile: Apply after import to reconcile fields not returned by the API
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile (should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy all managed OAuth security resources
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

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
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-apply: Apply using lab credentials
lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

## lab-update: Apply with updated description fields to verify in-place update path.
lab-update:
	@echo "==> Step 1: update descriptions (in-place update path)..."
	$(LAB_ENV) TF_VAR_role_description="Updated Terraform role description" \
	           TF_VAR_claim_description="Updated Terraform claim description" \
	           $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) TF_VAR_role_description="Updated Terraform role description" \
	           TF_VAR_claim_description="Updated Terraform claim description" \
	           $(MAKE) plan SUFFIX=$(SUFFIX)
	@echo "==> Step 2: revert to defaults; verify no forced replacement..."
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-import-all: Import all resources using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

## lab-reconcile: Reconcile after import
lab-reconcile:
	$(LAB_ENV) $(MAKE) reconcile SUFFIX=$(SUFFIX)

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

## lab-destroy: Destroy all managed resources using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → update → import-all → reconcile → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle

# ---------------------------------------------------------------------------
# Opt-in PR #228 lab check (NOT part of `lifecycle`; self-cleaning)
# ---------------------------------------------------------------------------
## lab-import-name-check: PR #228 check -- keyfactor_oauth_security_role imports by NAME (not ID), plans clean
##   afterwards, and a differently-cased name still imports (Command role names are case-insensitive) with a
##   WARNING naming both the supplied and the actual value. Applies, runs both imports, destroys.
lab-import-name-check:
	@set -e; LOG=$$(mktemp); trap 'rm -f "$$LOG"' EXIT; \
	 echo "==> [1/7] apply"; \
	 $(LAB_ENV) $(MAKE) --no-print-directory apply SUFFIX=$(SUFFIX) >/dev/null; \
	 NAME=$$($(LAB_ENV) $(UNSET_BASIC) $(TF) output -raw role_name); UPPER=$$(echo "$$NAME" | tr 'a-z' 'A-Z'); \
	 echo "    role name: $$NAME  (case variant: $$UPPER)"; \
	 RC=0; \
	 echo "==> [2/7] state rm role; import by exact NAME"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) state rm keyfactor_oauth_security_role.demo | tail -1; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) import -no-color -var="suffix=$(SUFFIX)" keyfactor_oauth_security_role.demo "$$NAME" > "$$LOG" 2>&1 || RC=$$?; \
	 echo "    import exit $$RC"; grep -nE "Import successful|Warning|Error|imported" "$$LOG" | cut -c1-250 || true; \
	 echo "==> [3/7] plan after name import (expect No changes)"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) plan -no-color -detailed-exitcode -var="suffix=$(SUFFIX)" > "$$LOG" 2>&1 || true; \
	 grep -nE "No changes|Plan:|will be|must be|~ |Error" "$$LOG" | cut -c1-250 || true; \
	 echo "==> [4/7] state rm role; import by CASE-VARIANT name $$UPPER"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) state rm keyfactor_oauth_security_role.demo | tail -1; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) import -no-color -var="suffix=$(SUFFIX)" keyfactor_oauth_security_role.demo "$$UPPER" > "$$LOG" 2>&1 || RC=$$?; \
	 echo "    import exit $$RC"; grep -nE -A6 "Warning|Error" "$$LOG" | cut -c1-300 || true; \
	 echo "==> [5/7] plan after case-variant import (expect No changes)"; \
	 $(LAB_ENV) $(UNSET_BASIC) $(TF) plan -no-color -detailed-exitcode -var="suffix=$(SUFFIX)" > "$$LOG" 2>&1 || true; \
	 grep -nE "No changes|Plan:|will be|must be|~ |Error" "$$LOG" | cut -c1-250 || true; \
	 echo "==> [6/7] destroy"; \
	 $(LAB_ENV) $(MAKE) --no-print-directory destroy SUFFIX=$(SUFFIX) 2>&1 | grep -E "Destroy complete|Error"; \
	 echo "==> [7/7] done (import exits accumulated: $$RC)"; exit $$RC

.PHONY: lab-import-name-check
