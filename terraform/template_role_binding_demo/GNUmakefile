## template_role_binding_demo/GNUmakefile
##
## Full-lifecycle smoke test for keyfactor_template_role_binding, covering
## PR #179's fix to Read()'s swallowed GetTemplates() API error:
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## Usage:
##   cd terraform/template_role_binding_demo
##   make build
##   make init
##   make lifecycle
##   make SUFFIX=_MYORG lifecycle

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the role and template role binding
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove both managed resources from state then re-import by role name
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	@echo "==> Extracting role name from state..."
	@ROLE_NAME=$$($(UNSET_BASIC) $(TF) output -raw role_name 2>/dev/null) && \
	 echo "Role Name=$$ROLE_NAME" && \
	 echo "==> Removing from state..." && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_template_role_binding.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_role.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 echo "==> Re-importing keyfactor_role by name..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_role.demo "$$ROLE_NAME" && \
	 echo "==> Re-importing keyfactor_template_role_binding by role name..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_template_role_binding.demo "$$ROLE_NAME"

## reconcile: Apply after import to reconcile fields not returned by the API
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the managed resources
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow — build, init, validate, plan, apply, import-all, reconcile, drift-check, destroy
all: build init validate plan apply import-all reconcile drift-check destroy

# ---------------------------------------------------------------------------
# Lab convenience targets (source KEYFACTOR_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-plan: Plan using lab credentials
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

## lab-apply: Apply using lab credentials
lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

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

## lifecycle: Full lifecycle: apply → import-all → reconcile → drift-check → destroy
##
##   KNOWN PROVIDER/SDK BUG: lab-apply is expected to FAIL here with "Error
##   updating template in Keyfactor: 'Policies' cannot be empty" -- Command
##   now requires a field on template update that keyfactor-go-client/v3's
##   UpdateTemplateArg request model does not send (same gap independently
##   noted in certificate_template_demo/main.tf). keyfactor_role.demo is
##   still created successfully before that failure, so every prerequisite
##   after lab-apply would normally be skipped by default GNU Make semantics
##   -- this target captures lab-apply's exit code instead so lab-destroy
##   ALWAYS runs and the role is never left orphaned on the lab.
lifecycle:
	@APPLY_EXIT=0; \
	 if ! $(MAKE) lab-apply SUFFIX=$(SUFFIX); then APPLY_EXIT=1; fi; \
	 if [ $$APPLY_EXIT -eq 0 ]; then \
	   $(MAKE) lab-import-all SUFFIX=$(SUFFIX) || exit 1; \
	   $(MAKE) lab-reconcile SUFFIX=$(SUFFIX) || exit 1; \
	   $(MAKE) lab-drift-check SUFFIX=$(SUFFIX) || exit 1; \
	 else \
	   echo "==> Skipping lab-import-all/lab-reconcile/lab-drift-check -- lab-apply failed (see summary below)."; \
	 fi; \
	 if ! $(MAKE) lab-destroy SUFFIX=$(SUFFIX); then \
	   echo "FAIL (harness): lab-destroy failed -- see above. keyfactor_role.demo (TemplateRoleBindingDemo$(SUFFIX)) may be orphaned; check manually."; \
	   exit 1; \
	 fi; \
	 echo "=============================================================="; \
	 echo "template_role_binding_demo summary:"; \
	 if [ $$APPLY_EXIT -ne 0 ]; then \
	   echo "  lab-apply: KNOWN PROVIDER/SDK BUG reproduced ('Policies' cannot be empty). See GNUmakefile lifecycle header."; \
	 else \
	   echo "  lab-apply: PASS (no 'Policies' error)."; \
	 fi; \
	 echo "=============================================================="; \
	 if [ $$APPLY_EXIT -ne 0 ]; then exit 1; fi

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all \
        lab-plan lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle
