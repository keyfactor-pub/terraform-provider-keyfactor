## security_role_permissions_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of the legacy keyfactor_role resource,
## and proves PR #179 (make `permissions` Optional+Computed to fix
## "Provider produced inconsistent result after apply" when an unrelated
## Update omits `permissions` from config):
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## This is a SEPARATE demo from ../security_role_demo/ (left untouched --
## that one proves the different PR #178 out-of-band drift-detection fix via
## its `lab-oob-drift` target). Both fixes live in resource_keyfactor_security_role.go.
##
## The `lab-omit-permissions-update` target is the actual regression proof for
## PR #179: it applies the role WITH permissions declared, then applies again
## with `description` changed (an unrelated attribute) AND `permissions`
## omitted from config entirely -- this must succeed without the
## inconsistent-result crash, and the role's permissions must remain intact
## server-side afterward.
##
## Usage:
##   cd terraform/security_role_permissions_demo
##   make build              # compile + install the provider locally
##   make init               # terraform init
##   make all                # run the full workflow
##   make SUFFIX=_MYORG all  # run with a custom name suffix

PROVIDER_ROOT  := $(abspath ../..)
PROVIDER_BIN   := $(HOME)/go/bin
SUFFIX         ?= _TF

TF            := TF_CLI_CONFIG_FILE=.terraformrc terraform
UNSET_BASIC   := unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN;

# ---------------------------------------------------------------------------
# Lab environment helpers
# Source LAB_ENV_FILE for OAuth credentials.
# Override via: make LAB_ENV_FILE=~/.env_other lifecycle
# ---------------------------------------------------------------------------
SHELL         := /bin/bash
LAB_ENV_FILE  ?= $(HOME)/.env_ses2541
LAB_TIMEOUT   ?= 600

LAB_ENV := set -a && source $(LAB_ENV_FILE) && set +a && \
           unset KEYFACTOR_USERNAME KEYFACTOR_PASSWORD KEYFACTOR_DOMAIN && \
           export KEYFACTOR_CLIENT_TIMEOUT=$(LAB_TIMEOUT) &&

# ---------------------------------------------------------------------------
# Provider build
# ---------------------------------------------------------------------------

## build: Compile and install the provider binary to ~/go/bin
build:
	@echo "==> Building provider..."
	cd $(PROVIDER_ROOT) && go install .
	@echo "==> Provider installed to $(PROVIDER_BIN)/terraform-provider-keyfactor"

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

## init: Initialize the Terraform working directory
init:
	$(UNSET_BASIC) $(TF) init

## validate: Validate the Terraform configuration
validate:
	$(UNSET_BASIC) $(TF) validate

## plan: Show the execution plan
plan:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## apply: Create the security role resource
apply:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## import-all: Remove the managed resource from state then re-import by its real name
import-all:
	@echo "==> Capturing state..."
	$(UNSET_BASIC) $(TF) show -json > tf_state.json
	@echo "==> Extracting IDs from state..."
	@ROLE_NAME=$$($(UNSET_BASIC) $(TF) output -raw role_name 2>/dev/null) && \
	 ROLE_ID=$$($(UNSET_BASIC) $(TF) output -raw role_id 2>/dev/null) && \
	 echo "Role Name=$$ROLE_NAME  Role ID=$$ROLE_ID" && \
	 echo "==> Removing from state..." && \
	 $(UNSET_BASIC) $(TF) state rm keyfactor_role.demo 2>&1 | grep -E "Removed|Successfully" || true && \
	 echo "==> Re-importing by real name..." && \
	 $(UNSET_BASIC) $(TF) import -var="suffix=$(SUFFIX)" keyfactor_role.demo "$$ROLE_NAME"

## reconcile: Apply after import to reconcile fields not returned by the API
reconcile:
	$(UNSET_BASIC) $(TF) apply -auto-approve -var="suffix=$(SUFFIX)"

## drift-check: Plan after reconcile — should show "No changes"
drift-check:
	$(UNSET_BASIC) $(TF) plan -var="suffix=$(SUFFIX)"

## destroy: Destroy the managed security role resource
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

## demo-no-destroy: Run workflow without final destroy (leaves resources on server)
demo-no-destroy: build init validate plan apply import-all reconcile drift-check

# ---------------------------------------------------------------------------
# Lab convenience targets (source LAB_ENV_FILE automatically)
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
lifecycle: lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy

# ---------------------------------------------------------------------------
# PR #179 regression proof — permissions omitted on an unrelated Update
#
#   1. apply with permissions declared (permissions_declared=true) and an
#      initial description
#   2. apply again with description CHANGED (the unrelated attribute) AND
#      permissions omitted from config (permissions_declared=false) --
#      pre-fix this crashed terraform apply with "Provider produced
#      inconsistent result after apply: .permissions: was null, but now
#      cty.ListVal(...)"; post-fix this must succeed cleanly
#   3. verify via a direct Command REST API call that the role's permissions
#      are still intact server-side (preserved, not cleared)
#   4. destroy
# ---------------------------------------------------------------------------

## lab-omit-permissions-update: Regression proof for PR179 (permissions Optional+Computed fix)
lab-omit-permissions-update:
	@echo "==> [1/4] apply WITH permissions declared..."
	$(LAB_ENV) $(TF) apply -auto-approve \
	  -var="suffix=$(SUFFIX)" \
	  -var="role_description=Initial description (PR179 demo)" \
	  -var="permissions_declared=true"
	@echo "==> [2/4] apply again: description changed (unrelated attribute), permissions OMITTED from config..."
	@$(LAB_ENV) $(TF) apply -auto-approve -no-color \
	  -var="suffix=$(SUFFIX)" \
	  -var="role_description=Updated description -- unrelated Update (PR179 demo)" \
	  -var="permissions_declared=false" > /tmp/security_role_permissions_demo_apply2.txt 2>&1; \
	 APPLY_EXIT=$$?; \
	 cat /tmp/security_role_permissions_demo_apply2.txt; \
	 if [ $$APPLY_EXIT -eq 0 ]; then \
	   echo "PASS: apply succeeded with permissions omitted on an unrelated Update (PR179 fix confirmed)."; \
	 else \
	   echo "FAIL: apply failed (exit $$APPLY_EXIT) -- inconsistent-result-after-apply regression."; \
	   exit 1; \
	 fi
	@echo "==> [3/4] verify permissions are still intact server-side (direct Command API call)..."
	@$(LAB_ENV) \
	 ROLE_ID=$$($(TF) output -raw role_id) && \
	 ROLE_NAME=$$($(TF) output -raw role_name) && \
	 echo "    target role: $$ROLE_NAME (id $$ROLE_ID)" && \
	 TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
	   -d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
	   | jq -r '.access_token') && \
	 curl -sk "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Security/Roles/$$ROLE_ID" \
	   -H "x-keyfactor-requested-with: APIClient" \
	   -H "x-keyfactor-api-version: 1" \
	   -H "Authorization: Bearer $$TOKEN" > /tmp/security_role_permissions_demo_verify.json && \
	 cat /tmp/security_role_permissions_demo_verify.json | jq . && \
	 if jq -e '.Permissions | index("Certificates:Read")' /tmp/security_role_permissions_demo_verify.json > /dev/null; then \
	   echo "PASS: server-side permissions still contain Certificates:Read -- preserved, not cleared."; \
	 else \
	   echo "FAIL: server-side permissions no longer contain Certificates:Read -- permissions were cleared."; \
	   exit 1; \
	 fi
	@echo "==> [4/4] destroy..."
	$(LAB_ENV) $(TF) destroy -auto-approve \
	  -var="suffix=$(SUFFIX)" \
	  -var="role_description=Updated description -- unrelated Update (PR179 demo)" \
	  -var="permissions_declared=false"

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle lab-omit-permissions-update
