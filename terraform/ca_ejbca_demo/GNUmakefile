## ca_ejbca_demo/GNUmakefile
##
## keyfactor_certificate_authority (ca_type=1, HTTPS/AnyCA REST Gateway)
## create+update lifecycle demo, exercising the OAuth connector fields
## (client_id/client_secret/token_url/scope/audience).
##
## REQUIRES real, working OAuth credentials for the target gateway --
## TF_VAR_ca_client_id / TF_VAR_ca_client_secret / TF_VAR_ca_token_url have
## no defaults (see variables.tf) and MUST be supplied for apply (not
## required for init/validate). Never commit real values.
##
## Usage:
##   cd terraform/ca_ejbca_demo
##   make build
##   make init
##   make validate
##   TF_VAR_ca_client_id=... TF_VAR_ca_client_secret=... TF_VAR_ca_token_url=... make lifecycle

include ../demo-common.mk

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create/update the demo CA connector
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove and re-import the CA by ID
import-all:
	@CA_ID=$$($(UNSET_BASIC) $(TF) output -raw ca_id 2>/dev/null); \
	 if [ -z "$$CA_ID" ]; then echo "Nothing in state to import."; exit 1; fi; \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_certificate_authority.demo 2>&1 | grep -E "Removed|Successfully" || true; \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_certificate_authority.demo "$$CA_ID"

## drift-check: Plan after import — should show "No changes" (client_secret is write-only)
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the demo CA connector
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json terraform.tfstate terraform.tfstate.backup terraform.tfstate.*.backup

## all: Full workflow — build, init, validate, plan, apply, import-all, drift-check, destroy
all: build init validate plan apply import-all drift-check destroy

## lab-plan / lab-apply / lab-import-all / lab-drift-check / lab-destroy:
## Same as above, sourcing KEYFACTOR_ENV_FILE automatically.
lab-plan:
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

lab-apply:
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)

## lab-update: Rotate scope/audience/client_secret to exercise Update()
lab-update:
	@echo "==> Step 1: rotate scope/audience (in-place update path)..."
	$(LAB_ENV) TF_VAR_ca_scope="ejbca_scope_updated" \
	           TF_VAR_ca_audience="ejbca_audience_updated" \
	           $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) TF_VAR_ca_scope="ejbca_scope_updated" \
	           TF_VAR_ca_audience="ejbca_audience_updated" \
	           $(MAKE) plan SUFFIX=$(SUFFIX)
	@echo "==> Step 2: revert to defaults — verify no forced replacement..."
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	$(LAB_ENV) $(MAKE) plan SUFFIX=$(SUFFIX)

lab-import-all:
	$(LAB_ENV) $(MAKE) import-all SUFFIX=$(SUFFIX)

lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check SUFFIX=$(SUFFIX)

lab-destroy:
	$(LAB_ENV) $(MAKE) destroy SUFFIX=$(SUFFIX)

## lifecycle: Full lifecycle: apply → update → import-all → apply (reconcile) → drift-check → destroy
##   REQUIRES TF_VAR_ca_client_id/ca_client_secret/ca_token_url to be set.
## NOTE: the reconcile step below deliberately invokes lab-apply as its own
##   $(MAKE) call, separate from the earlier lab-apply -- GNU Make treats a
##   .PHONY target as already "up to date" for the rest of a single make
##   process once it has run once, so `$(MAKE) lab-apply lab-update ...
##   lab-apply ...` (multiple goals in ONE make invocation) silently skips
##   the second lab-apply ("Nothing to be done for lab-apply"), and so would
##   a prerequisite list with a repeated name. Each `$(MAKE) target` line
##   below is a separate make PROCESS, which has no such memory, so the
##   reconcile actually runs. Confirmed empirically 2026-08-08.
lifecycle:
	@if [ -z "$$TF_VAR_ca_client_id" ] || [ -z "$$TF_VAR_ca_client_secret" ] || [ -z "$$TF_VAR_ca_token_url" ]; then \
	  echo "SKIPPED: ca_ejbca_demo requires TF_VAR_ca_client_id / TF_VAR_ca_client_secret / TF_VAR_ca_token_url for the target gateway (no defaults -- see variables.tf)."; \
	  exit 0; \
	fi; \
	$(MAKE) lab-apply && \
	$(MAKE) lab-update && \
	$(MAKE) lab-import-all && \
	$(MAKE) lab-apply && \
	$(MAKE) lab-drift-check && \
	$(MAKE) lab-destroy

.PHONY: build init validate plan apply import-all drift-check destroy clean all \
        lab-plan lab-apply lab-update lab-import-all lab-drift-check lab-destroy lifecycle
