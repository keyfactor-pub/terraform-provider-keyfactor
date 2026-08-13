## store_type_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of keyfactor_certificate_store_type resources:
##   build → init → validate → apply (data) → generate → plan → apply → import → destroy
##
## Usage:
##   cd terraform/store_type_demo
##   make build          # compile + install the provider locally
##   make init           # terraform init
##   make all            # run the full workflow
##   make SUFFIX=_MY_ORG generate  # regenerate with custom suffix

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## apply-data: Apply only the data sources (discovers all store types, saves state)
apply-data:
	$(UNSET_BASIC) $(TF) apply -auto-approve -target=data.keyfactor_certificate_store_types.all

## generate: Generate store_types.tf from live state with SUFFIX appended to short_name/capability/name.
##   Clones a representative ~10-type subset by default (see
##   gen_store_types.py's DEFAULT_REPRESENTATIVE_SHORT_NAMES), not the full
##   ~71-type fleet -- cloning everything left 213 orphaned clones in an
##   earlier iteration of this harness. Pass ONLY=ALL to clone every type.
ONLY ?=
generate: apply-data
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 gen_store_types.py --suffix "$(SUFFIX)" --state tf_state.json --out store_types.tf $(if $(ONLY),--only "$(ONLY)",)
	@echo "==> Generated store_types.tf ($(SUFFIX) suffix)"

## plan: Show the execution plan for all resources
plan:
	$(UNSET_BASIC) $(TF) plan

## apply: Create all store type resources (adds SUFFIX to short_name/name/capability)
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve

## import-all: Remove all managed resources from state then re-import by short_name
import-all:
	@echo "==> Exporting name/ID pairs from state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 _export_ids.py
	@echo "==> Removing from state..."
	@while IFS=' ' read -r name id sn; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_certificate_store_type.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by short_name..."
	@while IFS=' ' read -r name id sn; do \
	  result=$$($(UNSET_BASIC) $(TF) import "keyfactor_certificate_store_type.$$name" "$$sn" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name ($$sn)"; \
	  else \
	    echo "FAIL: $$name ($$sn)"; \
	    echo "$$result" | tail -3; \
	  fi; \
	done < _import_pairs.txt

## drift-check: Plan after import — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan

## destroy: Destroy all managed store type resources
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve

## clean: Remove generated files (state, generated tf, import pairs)
clean:
	rm -f tf_state.json store_types.tf _import_pairs.txt terraform.tfstate terraform.tfstate.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow — build, init, validate, apply-data, generate, plan, apply, import-all, drift-check, destroy
all: build init validate generate plan apply import-all drift-check destroy

## demo-no-destroy: Run workflow without final destroy (leaves resources on server)
demo-no-destroy: build init validate generate plan apply import-all drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source KEYFACTOR_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-generate: Discover store types and generate store_types.tf using lab credentials
lab-generate:
	$(LAB_ENV) $(MAKE) generate SUFFIX=$(SUFFIX)

## lab-plan: Plan using lab credentials
lab-plan:
	$(LAB_ENV) $(MAKE) plan

## lab-apply: Apply using lab credentials
lab-apply:
	$(LAB_ENV) $(MAKE) apply

## lab-update: Re-apply to verify idempotency (store type fields are fully managed — re-apply = no-op)
## Also verifies zero drift immediately after apply.
lab-update:
	@echo "==> Verifying idempotent re-apply (in-place update with no config change)..."
	$(LAB_ENV) $(MAKE) apply
	$(LAB_ENV) $(MAKE) plan

## lab-import-all: Import all store types using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check

## lab-destroy: Destroy all managed store types using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy

## lifecycle: Full lifecycle: generate → apply → update → import-all → drift-check → destroy
##
##   KNOWN PROVIDER BUG: lab-apply is expected to FAIL on the currently
##   released provider (2.9.1) with "Provider produced inconsistent result
##   after apply: .entry_parameters: was cty.ListValEmpty(...), but now
##   null" for several store types (confirmed 2026-08-07). That failure is a
##   genuine provider bug reproduction, not a harness defect -- but Terraform
##   still creates the store type server-side before the post-apply
##   consistency check fails, so every prerequisite after lab-apply is
##   skipped by default GNU Make semantics UNLESS we capture the failure
##   ourselves and keep going. This target does that: lab-apply's exit code
##   is captured (not chained via prerequisite list), update/import-all/
##   drift-check are skipped when it fails (state is inconsistent to work
##   with), but lab-destroy ALWAYS runs so no _TF store type is ever left
##   orphaned on the lab, and the known bug is never silently swallowed.
lifecycle:
	@APPLY_EXIT=0; \
	 $(MAKE) lab-generate SUFFIX=$(SUFFIX) || exit 1; \
	 if ! $(MAKE) lab-apply; then APPLY_EXIT=1; fi; \
	 if [ $$APPLY_EXIT -eq 0 ]; then \
	   $(MAKE) lab-update || exit 1; \
	   $(MAKE) lab-import-all || exit 1; \
	   $(MAKE) lab-drift-check || exit 1; \
	 else \
	   echo "==> Skipping lab-update/lab-import-all/lab-drift-check -- lab-apply failed (see summary below)."; \
	 fi; \
	 if ! $(MAKE) lab-destroy; then \
	   echo "FAIL (harness): lab-destroy failed -- see above. Demo store types may be orphaned; check manually (e.g. any short_name ending in \"$(SUFFIX)\")."; \
	   exit 1; \
	 fi; \
	 echo "=============================================================="; \
	 echo "store_type_demo summary:"; \
	 if [ $$APPLY_EXIT -ne 0 ]; then \
	   echo "  lab-apply: KNOWN PROVIDER BUG reproduced (entry_parameters empty-list -> null inconsistent result). See GNUmakefile lifecycle header."; \
	 else \
	   echo "  lab-apply: PASS (no inconsistent-result error)."; \
	 fi; \
	 echo "=============================================================="; \
	 if [ $$APPLY_EXIT -ne 0 ]; then exit 1; fi

.PHONY: build init validate apply-data generate plan apply import-all drift-check destroy clean all demo-no-destroy \
        lab-generate lab-plan lab-apply lab-update lab-import-all lab-drift-check lab-destroy lifecycle
