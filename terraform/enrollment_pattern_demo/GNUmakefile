## enrollment_pattern_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of the keyfactor_enrollment_pattern
## resource (plus its data source gap-fill):
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/enrollment_pattern_demo
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

## apply: Create the enrollment pattern resource
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove the managed pattern from state then re-import by numeric ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 ../_export_ids.py keyfactor_enrollment_pattern
	@echo "==> Removing from state..."
	@while IFS=' ' read -r name id; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_enrollment_pattern.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by numeric ID..."
	@while IFS=' ' read -r name id; do \
	  result=$$($(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" "keyfactor_enrollment_pattern.$$name" "$$id" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name (ID=$$id)"; \
	  else \
	    echo "FAIL: $$name (ID=$$id)"; \
	    echo "$$result" | tail -3; \
	  fi; \
	done < _import_pairs.txt

## reconcile: Apply after import to settle any remaining Computed-only
## fields. `associated_role_names`/`certificate_authority_ids` no longer
## need reconciling here -- they're derived from GetById's response on
## import itself (see resource_keyfactor_enrollment_pattern.go) -- so this
## step is now typically a no-op ("No changes") immediately after import.
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the managed enrollment pattern resource
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json _import_pairs.txt terraform.tfstate terraform.tfstate.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow — build, init, validate, plan, apply, import-all, reconcile, drift-check, destroy
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

## lab-update: Apply with an updated description AND changed driver
## attributes (associated_role_names, certificate_authority_ids,
## policies.default_certificate_owner_role_id) to verify the in-place
## update path -- full-review Phase 1 required tests, item 3: this demo
## previously never touched these fields, which is why the mirror-pinning
## bugs (F2/F4) shipped undetected despite a green harness. Plan after each
## apply should show "No changes".
lab-update:
	@echo "==> Step 1: update description + driver attributes (in-place update)..."
	$(LAB_ENV) TF_VAR_description_override="Updated by harness" \
	  TF_VAR_associated_role_name="Administrator" \
	  TF_VAR_owner_role_name="Administrator" \
	  TF_VAR_ca_name="OpenBao Root CA" \
	  $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) TF_VAR_description_override="Updated by harness" \
	  TF_VAR_associated_role_name="Administrator" \
	  TF_VAR_owner_role_name="Administrator" \
	  TF_VAR_ca_name="OpenBao Root CA" \
	  $(MAKE) plan SUFFIX=$(SUFFIX)
	@echo "==> Step 2: revert to defaults..."
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-import-all: Import the enrollment pattern using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

## lab-reconcile: Re-apply after import to settle any remaining Computed-only
## fields (see reconcile's comment above -- typically a no-op now)
lab-reconcile:
	$(LAB_ENV) $(MAKE) reconcile SUFFIX=$(SUFFIX)

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

## lab-destroy: Destroy the managed enrollment pattern using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → update → import-all → reconcile → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle
