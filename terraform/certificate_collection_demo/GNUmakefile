## certificate_collection_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of the keyfactor_certificate_collection
## resource (plus its data source gap-fill):
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/certificate_collection_demo
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

## apply: Create the certificate collection resource
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove the managed collection from state then re-import by numeric ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 ../_export_ids.py keyfactor_certificate_collection
	@echo "==> Removing from state..."
	@while IFS=' ' read -r name id; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_certificate_collection.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by numeric ID..."
	@while IFS=' ' read -r name id; do \
	  result=$$($(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" "keyfactor_certificate_collection.$$name" "$$id" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name (ID=$$id)"; \
	  else \
	    echo "FAIL: $$name (ID=$$id)"; \
	    echo "$$result" | tail -3; \
	  fi; \
	done < _import_pairs.txt

## reconcile: Apply after import to reconcile fields not returned by the API
## (e.g. `query`, which GetById never returns -- see resource_keyfactor_certificate_collection.go).
## Should produce no further changes beyond re-declaring write-only fields.
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile (should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the managed certificate collection resource
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json _import_pairs.txt terraform.tfstate terraform.tfstate.backup

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

## lab-update: Apply with an updated description AND changed query to verify
## the in-place update path -- full-review Phase 1 required tests, item 3:
## this demo previously never touched query on update, which is why the
## content mirror follow-the-driver bug (F3) shipped undetected despite a
## green harness. Plan after each apply should show "No changes".
lab-update:
	@echo "==> Step 1: update description + query (in-place update)..."
	$(LAB_ENV) TF_VAR_description_override="Updated by harness" \
	  TF_VAR_query_override="IssuedDN -contains \"demo-updated\"" \
	  $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) TF_VAR_description_override="Updated by harness" \
	  TF_VAR_query_override="IssuedDN -contains \"demo-updated\"" \
	  $(MAKE) plan SUFFIX=$(SUFFIX)
	@echo "==> Step 2: revert to defaults..."
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-import-all: Import the certificate collection using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

## lab-reconcile: Reconcile after import (re-apply to settle write-only field drift)
lab-reconcile:
	$(LAB_ENV) $(MAKE) reconcile SUFFIX=$(SUFFIX)

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

## lab-destroy: Destroy the managed certificate collection using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → update → import-all → reconcile → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle
