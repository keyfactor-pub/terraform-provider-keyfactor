## certificate_pfx_demo/GNUmakefile
##
## Demonstrates PFX certificate enrollment via the keyfactor_certificate resource:
##   build → init → validate → plan → apply → import → drift-check → destroy
##
## Prerequisites — set these environment variables before running:
##   export KEYFACTOR_HOSTNAME=your-command-host.example.com
##   export KEYFACTOR_AUTH_CLIENT_ID=your-client-id
##   export KEYFACTOR_AUTH_CLIENT_SECRET=your-client-secret
##   export KEYFACTOR_AUTH_TOKEN_URL=https://auth.example.com/connect/token
##   export TF_VAR_certificate_authority="OpenBao PKI"
##   export TF_VAR_certificate_template="AnyCA_lab-role"
##
## Usage:
##   cd terraform/certificate_pfx_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make all                # run the full workflow
##   make SUFFIX=_MYORG all  # run with a custom CN suffix

LAB_CA        ?= OpenBao PKI
LAB_PATTERN   ?= Lab - AnyCA (lab-role)
LAB_ENV_EXTRA_EXPORTS = TF_VAR_certificate_authority="$(LAB_CA)" TF_VAR_certificate_enrollment_pattern="$(LAB_PATTERN)"

include ../demo-common.mk

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Enroll all demo certificates
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove all managed resources from state then re-import by certificate ID
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	python3 ../_export_ids.py keyfactor_certificate certificate_id
	@echo "==> Removing from state..."
	@while IFS=' ' read -r name id; do \
	  $(UNSET_BASIC) $(TF) state rm "keyfactor_certificate.$$name" 2>&1 | grep Removed; \
	done < _import_pairs.txt
	@echo "==> Re-importing by certificate ID..."
	@while IFS=' ' read -r name id; do \
	  result=$$($(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" "keyfactor_certificate.$$name" "$$id" 2>&1); \
	  if echo "$$result" | grep -q "Import successful"; then \
	    echo "OK: $$name (ID=$$id)"; \
	  else \
	    echo "FAIL: $$name (ID=$$id)"; \
	    echo "$$result" | tail -3; \
	  fi; \
	done < _import_pairs.txt

## drift-check: Plan after import — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Revoke and delete all demo certificates
destroy:
	$(UNSET_BASIC) $(TF) destroy -auto-approve -var="suffix=$(SUFFIX)"

## clean: Remove generated files
clean:
	rm -f tf_state.json _import_pairs.txt terraform.tfstate terraform.tfstate.backup

# ---------------------------------------------------------------------------
# Combined workflows
# ---------------------------------------------------------------------------

## all: Full workflow — build, init, validate, plan, apply, import-all, drift-check, destroy
all: build init validate plan apply import-all drift-check destroy

## demo-no-destroy: Run workflow without final destroy (leaves certificates on server)
demo-no-destroy: build init validate plan apply import-all drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source KEYFACTOR_ENV_FILE automatically)
# ---------------------------------------------------------------------------

## lab-plan: Plan using lab credentials
lab-plan:
	$(LAB_ENV) $(MAKE) plan

## lab-apply: Apply using lab credentials from KEYFACTOR_ENV_FILE
lab-apply:
	$(LAB_ENV) $(MAKE) apply

## lab-update: Apply with updated metadata and renew_days to verify in-place update path.
## Also verifies full→minimal: re-applies with no metadata/renewal to confirm they are cleared.
lab-update:
	@echo "==> Step 1: update metadata and renew_days (in-place update path)..."
	$(LAB_ENV) TF_VAR_metadata_email="ops@example.com" \
	           TF_VAR_renew_days=60 \
	           $(MAKE) apply
	$(LAB_ENV) TF_VAR_metadata_email="ops@example.com" \
	           TF_VAR_renew_days=60 \
	           $(MAKE) plan
	@echo "==> Step 2: full→minimal — remove metadata and renewal_config from config..."
	@echo "==>   Expect: 1 in-place change (metadata + renewal cleared), 0 to destroy"
	$(LAB_ENV) TF_VAR_metadata_email="" \
	           TF_VAR_renew_days=0 \
	           $(MAKE) apply
	$(LAB_ENV) TF_VAR_metadata_email="" \
	           TF_VAR_renew_days=0 \
	           $(MAKE) plan

## lab-import-all: Import all certificates using lab credentials
lab-import-all:
	$(LAB_ENV) $(MAKE) import-all

## lab-drift-check: Drift-check using lab credentials
lab-drift-check:
	$(LAB_ENV) $(MAKE) drift-check

## lab-destroy: Destroy using lab credentials
lab-destroy:
	$(LAB_ENV) $(MAKE) destroy

## lifecycle: Full lifecycle: apply → update (apply+plan) → import-all → apply (reconcile) → drift-check → destroy
lifecycle: lab-apply lab-update lab-import-all lab-apply lab-drift-check lab-destroy

.PHONY: build init validate plan apply import-all drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-update lab-import-all lab-drift-check lab-destroy lifecycle
