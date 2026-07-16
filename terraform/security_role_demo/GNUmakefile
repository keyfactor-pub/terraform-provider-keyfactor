## security_role_demo/GNUmakefile
##
## Demonstrates end-to-end lifecycle of the legacy keyfactor_role
## resource, and proves PR #178 (detect out-of-band drift on Read):
##   build → init → validate → plan → apply → import → reconcile → drift-check → destroy
##
## The `lab-oob-drift` target is the actual regression proof for PR #178: it
## mutates the role's permissions directly via the Command REST API (bypassing
## Terraform), then asserts `terraform plan` reports drift instead of a false
## "No changes."
##
## Usage:
##   cd terraform/security_role_demo
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
# PR #178 regression proof — out-of-band drift detection
#
#   1. apply the Terraform-managed role
#   2. mutate its permissions directly via the Command REST API
#      (bypassing Terraform entirely)
#   3. plan — MUST show drift (this is the PR178 fix); "No changes" here
#      is a FAIL (that would mean the false-negative regressed)
#   4. apply again to reconcile the role back to the Terraform-managed value
#   5. plan again — MUST show "No changes"
#
# Uses `terraform plan -detailed-exitcode` for the assertion rather than
# grepping text: exit 0 = no changes, exit 2 = changes present, exit 1 = error.
# ---------------------------------------------------------------------------

## lab-oob-drift: Regression proof for PR178 (detect out-of-band drift on Read)
lab-oob-drift:
	@echo "==> [1/5] apply Terraform-managed role..."
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	@echo "==> [2/5] mutate permissions out-of-band via direct Command API call..."
	@$(LAB_ENV) \
	 ROLE_ID=$$($(TF) output -raw role_id) && \
	 ROLE_NAME=$$($(TF) output -raw role_name) && \
	 echo "    target role: $$ROLE_NAME (id $$ROLE_ID)" && \
	 TOKEN=$$(curl -sk -X POST "$$KEYFACTOR_AUTH_TOKEN_URL" \
	   -d "grant_type=client_credentials&client_id=$$KEYFACTOR_AUTH_CLIENT_ID&client_secret=$$KEYFACTOR_AUTH_CLIENT_SECRET" \
	   | jq -r '.access_token') && \
	 HTTP_STATUS=$$(curl -sk -o /tmp/security_role_demo_oob_response.json -w "%{http_code}" -X PUT \
	   "https://$$KEYFACTOR_HOSTNAME/$${KEYFACTOR_API_PATH:-Keyfactor/API}/Security/Roles" \
	   -H "x-keyfactor-requested-with: APIClient" \
	   -H "x-keyfactor-api-version: 1" \
	   -H "Content-Type: application/json" \
	   -H "Authorization: Bearer $$TOKEN" \
	   -d "{\"Id\":$$ROLE_ID,\"Name\":\"$$ROLE_NAME\",\"Description\":\"Mutated out-of-band by lab-oob-drift ($(SUFFIX))\",\"Permissions\":[\"Certificates:Read\",\"Certificates:EditMetadata\"]}") && \
	 echo "    PUT /Security/Roles HTTP status: $$HTTP_STATUS" && \
	 cat /tmp/security_role_demo_oob_response.json && echo && \
	 if [ "$$HTTP_STATUS" -lt 200 ] || [ "$$HTTP_STATUS" -ge 300 ]; then \
	   echo "FAIL: out-of-band API mutation did not succeed (HTTP $$HTTP_STATUS)"; \
	   exit 1; \
	 fi
	@echo "==> [3/5] plan — expect drift to be detected (PR178 regression proof)..."
	@$(LAB_ENV) $(TF) plan -var="suffix=$(SUFFIX)" -detailed-exitcode -no-color > /tmp/security_role_demo_oob_plan.txt 2>&1; \
	 PLAN_EXIT=$$?; \
	 cat /tmp/security_role_demo_oob_plan.txt; \
	 if [ $$PLAN_EXIT -eq 2 ]; then \
	   echo "PASS: terraform plan detected the out-of-band drift (PR178 fix confirmed)."; \
	 elif [ $$PLAN_EXIT -eq 0 ]; then \
	   echo "FAIL: terraform plan reported \"No changes\" despite out-of-band mutation -- drift detection regressed."; \
	   exit 1; \
	 else \
	   echo "FAIL: terraform plan errored (exit $$PLAN_EXIT)."; \
	   exit 1; \
	 fi
	@echo "==> [4/5] reconcile -- apply to restore the Terraform-managed value..."
	$(LAB_ENV) $(MAKE) apply SUFFIX=$(SUFFIX)
	@echo "==> [5/5] final drift-check -- expect \"No changes\"..."
	@$(LAB_ENV) $(TF) plan -var="suffix=$(SUFFIX)" -detailed-exitcode -no-color > /tmp/security_role_demo_oob_final_plan.txt 2>&1; \
	 PLAN_EXIT=$$?; \
	 cat /tmp/security_role_demo_oob_final_plan.txt; \
	 if [ $$PLAN_EXIT -eq 0 ]; then \
	   echo "PASS: final drift-check shows No changes -- reconciliation successful."; \
	 else \
	   echo "FAIL: final drift-check still shows drift (exit $$PLAN_EXIT)."; \
	   exit 1; \
	 fi

.PHONY: build init validate plan apply import-all reconcile drift-check destroy clean all demo-no-destroy \
        lab-plan lab-apply lab-import-all lab-reconcile lab-drift-check lab-destroy lifecycle lab-oob-drift
