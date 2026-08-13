## release_validation_demo/GNUmakefile
##
## Trimmed release-smoke test: agent lookup, 1 PFX + 1 CSR certificate, 6
## K8S certificate stores, 4 deployments -- a fast release-gate pass across
## the provider's most commonly used surfaces in a single apply.
##
## Usage:
##   cd terraform/release_validation_demo
##   make build
##   make init
##   make lifecycle

include ../demo-common.mk

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the certificates, stores, and deployments
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove certificates + stores from state then re-import by real ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 _export_ids.py
	@echo "==> Removing from state..."
	@while IFS=' ' read -r rtype name id; do \
	  $(UNSET_BASIC) $(TF) state rm "$$rtype.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by real ID..."
	@while IFS=' ' read -r rtype name id; do \
	  result=$$($(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" "$$rtype.$$name" "$$id" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$rtype.$$name (ID=$$id)"; \
	  else \
	    echo "FAIL: $$rtype.$$name (ID=$$id)"; \
	    echo "$$result" | tail -5; \
	  fi; \
	done < _import_pairs.txt

## drift-check: Plan after import — only write-only fields should appear as "to change"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy all managed resources
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json _import_pairs.txt terraform.tfstate terraform.tfstate.backup

## all: Full workflow — build, init, validate, plan, apply, import-all, drift-check, destroy
all: build init validate plan apply import-all drift-check destroy

## lab-plan / lab-apply / lab-import-all / lab-drift-check / lab-destroy:
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → import-all → drift-check → destroy
lifecycle: lab-apply lab-import-all lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all drift-check destroy clean all \
        lab-plan lab-apply lab-import-all lab-drift-check lab-destroy lifecycle
